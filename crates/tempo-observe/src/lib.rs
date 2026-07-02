//! tempo-observe - engine-agnostic observation compiler core.
//!
//! This crate owns the WS4 observation spine from `final.md`: stable NodeIds,
//! interactive-element ranking, changed-subtree diffs, set-of-marks metadata,
//! and token/byte budgeting. Live Servo/CDP adapters feed raw nodes into this
//! pure compiler; tests exercise the same path with AccessKit-style fixtures.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Cursor;

use tempo_schema::{
    CompiledObservation, InteractiveElement, NodeId, ObservationDiff, Provenance, TaintSpan,
};

/// Default serialized observation budget from `final.md` section 8.
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024;

/// Approximate token budget from `final.md` section 8.
pub const DEFAULT_MAX_TOKENS: usize = 1_500;

/// Default number of ranked elements that receive set-of-marks labels.
pub const DEFAULT_MAX_MARKS: usize = 16;

/// Compiler controls for observation size and set-of-marks output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileOptions {
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub max_marks: usize,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: DEFAULT_MAX_MARKS,
        }
    }
}

/// One raw interactive candidate emitted by an engine adapter or recorded fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct RawElement {
    pub source_id: Option<String>,
    pub stable_hint: Option<String>,
    pub role: String,
    pub name: Vec<TaintSpan>,
    pub value: Vec<TaintSpan>,
    pub bounds: Option<[f32; 4]>,
    pub visible: bool,
    pub enabled: bool,
    pub interactive: bool,
}

impl RawElement {
    /// Construct a visible, enabled, page-derived interactive candidate.
    pub fn new(role: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            source_id: None,
            stable_hint: None,
            role: role.into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: name.into(),
            }],
            value: Vec::new(),
            bounds: None,
            visible: true,
            enabled: true,
            interactive: true,
        }
    }

    pub fn source_id(mut self, source_id: impl Into<String>) -> Self {
        self.source_id = Some(source_id.into());
        self
    }

    pub fn stable_hint(mut self, stable_hint: impl Into<String>) -> Self {
        self.stable_hint = Some(stable_hint.into());
        self
    }

    pub fn name_spans(mut self, name: Vec<TaintSpan>) -> Self {
        self.name = name;
        self
    }

    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = vec![TaintSpan {
            provenance: Provenance::Page,
            text: value.into(),
        }];
        self
    }

    pub fn value_spans(mut self, value: Vec<TaintSpan>) -> Self {
        self.value = value;
        self
    }

    pub fn bounds(mut self, bounds: [f32; 4]) -> Self {
        self.bounds = Some(bounds);
        self
    }

    pub fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    fn source_key(&self) -> Option<String> {
        self.source_id.as_ref().map(|id| format!("source:{id}"))
    }

    fn fingerprint_key(&self) -> String {
        if let Some(stable_hint) = &self.stable_hint {
            return format!("hint:{}", normalize(stable_hint));
        }

        format!(
            "fp:role={};name={};value={}",
            normalize(&self.role),
            normalize(&span_text(&self.name)),
            normalize(&span_text(&self.value))
        )
    }

    fn allocation_key(&self) -> String {
        self.stable_hint
            .as_ref()
            .map(|hint| format!("hint:{}", normalize(hint)))
            .or_else(|| self.source_key())
            .unwrap_or_else(|| self.fingerprint_key())
    }
}

/// Raw observation input for one page snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservationInput {
    pub url: String,
    pub elements: Vec<RawElement>,
}

impl ObservationInput {
    pub fn new(url: impl Into<String>, elements: Vec<RawElement>) -> Self {
        Self {
            url: url.into(),
            elements,
        }
    }
}

/// Stateful compiler. The mapper remembers identities across snapshots so NodeIds
/// survive relayout, reorder, and re-render when either engine IDs or stable DOM
/// hints/fingerprints line up.
#[derive(Debug, Default)]
pub struct ObservationCompiler {
    seq: u64,
    mapper: StableIdMapper,
    options: CompileOptions,
}

impl ObservationCompiler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: CompileOptions) -> Self {
        Self {
            seq: 0,
            mapper: StableIdMapper::default(),
            options,
        }
    }

    /// Compile one raw snapshot into the frozen schema observation.
    pub fn compile(&mut self, input: ObservationInput) -> CompiledObservation {
        self.seq += 1;

        let mut elements: Vec<_> = input
            .elements
            .into_iter()
            .filter(|raw| raw.visible && raw.interactive)
            .map(|raw| {
                let node_id = self.mapper.node_id_for(&raw);
                let rank = rank_raw_element(&raw);
                InteractiveElement {
                    node_id,
                    role: raw.role,
                    name: raw.name,
                    value: raw.value,
                    bounds: raw.bounds,
                    rank,
                }
            })
            .collect();

        elements.sort_by(|left, right| {
            right
                .rank
                .total_cmp(&left.rank)
                .then_with(|| left.node_id.0.cmp(&right.node_id.0))
        });

        apply_budget(input.url, self.seq, elements, self.options)
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// Map source IDs and stable fingerprints to schema NodeIds.
#[derive(Debug, Default)]
pub struct StableIdMapper {
    by_source: HashMap<String, NodeId>,
    by_fingerprint: HashMap<String, NodeId>,
    allocated: HashSet<String>,
}

impl StableIdMapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_id_for(&mut self, raw: &RawElement) -> NodeId {
        if let Some(source_key) = raw.source_key() {
            if let Some(node_id) = self.by_source.get(&source_key) {
                return node_id.clone();
            }
        }

        let fingerprint = raw.fingerprint_key();
        if let Some(node_id) = self.by_fingerprint.get(&fingerprint) {
            if let Some(source_key) = raw.source_key() {
                self.by_source.insert(source_key, node_id.clone());
            }
            return node_id.clone();
        }

        let node_id = self.allocate(&raw.allocation_key());
        if let Some(source_key) = raw.source_key() {
            self.by_source.insert(source_key, node_id.clone());
        }
        self.by_fingerprint.insert(fingerprint, node_id.clone());
        node_id
    }

    fn allocate(&mut self, key: &str) -> NodeId {
        let base = format!("node:{:016x}", fnv1a64(key.as_bytes()));
        if self.allocated.insert(base.clone()) {
            return NodeId(base);
        }

        let mut suffix = 1_u64;
        loop {
            let candidate = format!("{base}-{suffix}");
            if self.allocated.insert(candidate.clone()) {
                return NodeId(candidate);
            }
            suffix += 1;
        }
    }
}

/// Deterministic ranker for interactive candidates.
pub fn rank_raw_element(raw: &RawElement) -> f32 {
    let role = raw.role.to_ascii_lowercase();
    let role_score = match role.as_str() {
        "textbox" | "searchbox" | "combobox" => 1.0,
        "button" | "menuitem" | "option" => 0.92,
        "link" => 0.78,
        "checkbox" | "radio" | "switch" | "slider" => 0.72,
        "tab" | "listbox" => 0.64,
        _ => 0.35,
    };

    let label_score = if span_text(&raw.name).trim().is_empty() {
        0.0
    } else {
        0.12
    };
    let value_score = if raw.value.is_empty() { 0.0 } else { 0.04 };
    let enabled_score = if raw.enabled { 0.04 } else { -0.20 };
    let area_score = raw.bounds.map(area_bonus).unwrap_or(0.0);

    (role_score + label_score + value_score + enabled_score + area_score).clamp(0.0, 1.25)
}

/// Build a diff between two compiled observations.
pub fn diff_observations(
    previous: &CompiledObservation,
    current: &CompiledObservation,
) -> ObservationDiff {
    let previous_by_id: HashMap<_, _> = previous
        .elements
        .iter()
        .map(|element| (element.node_id.clone(), element))
        .collect();
    let current_ids: HashSet<_> = current
        .elements
        .iter()
        .map(|element| element.node_id.clone())
        .collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for element in &current.elements {
        match previous_by_id.get(&element.node_id) {
            None => added.push(element.clone()),
            Some(previous_element) if *previous_element != element => changed.push(element.clone()),
            Some(_) => {}
        }
    }

    let removed = previous
        .elements
        .iter()
        .filter(|element| !current_ids.contains(&element.node_id))
        .map(|element| element.node_id.clone())
        .collect();

    ObservationDiff {
        since_seq: previous.seq,
        seq: current.seq,
        added,
        removed,
        changed,
    }
}

/// Errors returned by the set-of-marks bitmap compositor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MarkCompositorError {
    InvalidDimensions { width: u32, height: u32 },
    InvalidBufferLength { expected: usize, actual: usize },
    PngDecode(String),
    PngEncode(String),
}

impl fmt::Display for MarkCompositorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions { width, height } => {
                write!(formatter, "invalid screenshot dimensions: {width}x{height}")
            }
            Self::InvalidBufferLength { expected, actual } => write!(
                formatter,
                "invalid RGBA screenshot buffer length: expected {expected}, got {actual}"
            ),
            Self::PngDecode(error) => write!(formatter, "failed to decode PNG screenshot: {error}"),
            Self::PngEncode(error) => write!(formatter, "failed to encode PNG screenshot: {error}"),
        }
    }
}

impl std::error::Error for MarkCompositorError {}

/// Composite set-of-marks labels and bounds onto a PNG screenshot.
///
/// Driver screenshots are exposed as PNG bytes, while engines and tests may use
/// raw RGBA buffers internally. This helper decodes the PNG, applies the same
/// compositor as [`composite_set_of_marks_rgba`], then returns a PNG suitable for
/// MCP/BiDi screenshot surfaces.
pub fn composite_set_of_marks_png(
    screenshot_png: &[u8],
    observation: &CompiledObservation,
) -> Result<Vec<u8>, MarkCompositorError> {
    let decoded = decode_png_to_rgba(screenshot_png)?;
    let composited =
        composite_set_of_marks_rgba(&decoded.rgba, decoded.width, decoded.height, observation)?;
    encode_rgba_png(&composited, decoded.width, decoded.height)
}

/// Composite set-of-marks labels and bounds onto a raw RGBA screenshot.
///
/// The compositor uses the observation's `marks` list as the source of truth and
/// draws only elements that still have concrete bounds. Coordinates are clipped to
/// the screenshot so partially-visible elements still receive usable marks.
pub fn composite_set_of_marks_rgba(
    screenshot_rgba: &[u8],
    width: u32,
    height: u32,
    observation: &CompiledObservation,
) -> Result<Vec<u8>, MarkCompositorError> {
    let expected = rgba_len(width, height)?;
    if screenshot_rgba.len() != expected {
        return Err(MarkCompositorError::InvalidBufferLength {
            expected,
            actual: screenshot_rgba.len(),
        });
    }

    let mut output = screenshot_rgba.to_vec();
    let mut canvas = RgbaCanvas {
        pixels: &mut output,
        width,
        height,
    };
    for (node_id, label) in &observation.marks {
        let Some(element) = observation
            .elements
            .iter()
            .find(|candidate| candidate.node_id == *node_id)
        else {
            continue;
        };
        let Some(bounds) = element.bounds else {
            continue;
        };
        draw_mark(&mut canvas, bounds, *label);
    }
    Ok(output)
}

/// Serialized JSON byte length for a compiled observation.
pub fn serialized_len(observation: &CompiledObservation) -> usize {
    match serde_json::to_vec(observation) {
        Ok(bytes) => bytes.len(),
        Err(_) => usize::MAX,
    }
}

/// Coarse token estimate used for the budget gate.
pub fn estimated_tokens(observation: &CompiledObservation) -> usize {
    serialized_len(observation).div_ceil(4)
}

/// Stable crate summary used by smoke tests and binaries.
pub fn describe() -> &'static str {
    "observation compiler: stable-ID mapper, interactive-element ranker, diff engine, set-of-marks compositor, token budgeter"
}

fn apply_budget(
    url: String,
    seq: u64,
    mut elements: Vec<InteractiveElement>,
    options: CompileOptions,
) -> CompiledObservation {
    loop {
        let observation = make_observation(&url, seq, elements.clone(), options.max_marks);
        let within_byte_budget =
            options.max_bytes == 0 || serialized_len(&observation) <= options.max_bytes;
        let within_token_budget =
            options.max_tokens == 0 || estimated_tokens(&observation) <= options.max_tokens;

        if elements.is_empty() || (within_byte_budget && within_token_budget) {
            return observation;
        }

        elements.pop();
    }
}

fn make_observation(
    url: &str,
    seq: u64,
    elements: Vec<InteractiveElement>,
    max_marks: usize,
) -> CompiledObservation {
    let marks = elements
        .iter()
        .take(max_marks)
        .enumerate()
        .map(|(index, element)| (element.node_id.clone(), (index + 1) as u32))
        .collect();

    CompiledObservation {
        schema_version: tempo_schema::SCHEMA_VERSION.into(),
        url: url.into(),
        seq,
        elements,
        marks,
    }
}

fn area_bonus(bounds: [f32; 4]) -> f32 {
    let area = (bounds[2].max(0.0) * bounds[3].max(0.0)).min(40_000.0);
    (area / 40_000.0) * 0.08
}

fn rgba_len(width: u32, height: u32) -> Result<usize, MarkCompositorError> {
    if width == 0 || height == 0 {
        return Err(MarkCompositorError::InvalidDimensions { width, height });
    }
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(MarkCompositorError::InvalidDimensions { width, height })?;
    Ok(pixels)
}

struct DecodedRgbaImage {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

fn decode_png_to_rgba(screenshot_png: &[u8]) -> Result<DecodedRgbaImage, MarkCompositorError> {
    let mut decoder = png::Decoder::new(Cursor::new(screenshot_png));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|error| MarkCompositorError::PngDecode(error.to_string()))?;
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buffer)
        .map_err(|error| MarkCompositorError::PngDecode(error.to_string()))?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(MarkCompositorError::PngDecode(format!(
            "unsupported PNG bit depth after expansion: {:?}",
            info.bit_depth
        )));
    }

    let pixels = &buffer[..info.buffer_size()];
    let rgba = png_frame_to_rgba(pixels, info.width, info.height, info.color_type)?;
    Ok(DecodedRgbaImage {
        width: info.width,
        height: info.height,
        rgba,
    })
}

fn png_frame_to_rgba(
    pixels: &[u8],
    width: u32,
    height: u32,
    color_type: png::ColorType,
) -> Result<Vec<u8>, MarkCompositorError> {
    let pixel_count = rgba_len(width, height)? / 4;
    match color_type {
        png::ColorType::Rgba => {
            let expected = pixel_count * 4;
            if pixels.len() != expected {
                return Err(MarkCompositorError::PngDecode(format!(
                    "RGBA frame length mismatch: expected {expected}, got {}",
                    pixels.len()
                )));
            }
            Ok(pixels.to_vec())
        }
        png::ColorType::Rgb => {
            validate_png_frame_len(pixels, pixel_count, 3, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for chunk in pixels.chunks_exact(3) {
                rgba.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            Ok(rgba)
        }
        png::ColorType::Grayscale => {
            validate_png_frame_len(pixels, pixel_count, 1, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for gray in pixels {
                rgba.extend_from_slice(&[*gray, *gray, *gray, 255]);
            }
            Ok(rgba)
        }
        png::ColorType::GrayscaleAlpha => {
            validate_png_frame_len(pixels, pixel_count, 2, color_type)?;
            let mut rgba = Vec::with_capacity(pixel_count * 4);
            for chunk in pixels.chunks_exact(2) {
                rgba.extend_from_slice(&[chunk[0], chunk[0], chunk[0], chunk[1]]);
            }
            Ok(rgba)
        }
        png::ColorType::Indexed => Err(MarkCompositorError::PngDecode(
            "indexed PNG frame was not expanded to RGB".into(),
        )),
    }
}

fn validate_png_frame_len(
    pixels: &[u8],
    pixel_count: usize,
    channels: usize,
    color_type: png::ColorType,
) -> Result<(), MarkCompositorError> {
    let expected = pixel_count * channels;
    if pixels.len() == expected {
        Ok(())
    } else {
        Err(MarkCompositorError::PngDecode(format!(
            "{color_type:?} frame length mismatch: expected {expected}, got {}",
            pixels.len()
        )))
    }
}

fn encode_rgba_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, MarkCompositorError> {
    let expected = rgba_len(width, height)?;
    if rgba.len() != expected {
        return Err(MarkCompositorError::InvalidBufferLength {
            expected,
            actual: rgba.len(),
        });
    }

    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
        writer
            .write_image_data(rgba)
            .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct Rect {
    x0: u32,
    y0: u32,
    x1: u32,
    y1: u32,
}

struct RgbaCanvas<'a> {
    pixels: &'a mut [u8],
    width: u32,
    height: u32,
}

impl RgbaCanvas<'_> {
    fn draw_rect_outline(&mut self, rect: Rect, thickness: u32, color: [u8; 4]) {
        let x1 = rect.x1.min(self.width);
        let y1 = rect.y1.min(self.height);
        for offset in 0..thickness {
            let left = rect.x0.saturating_add(offset);
            let top = rect.y0.saturating_add(offset);
            if left >= x1 || top >= y1 {
                break;
            }
            self.draw_horizontal_line(rect.x0, x1, top, color);
            let bottom = y1.saturating_sub(offset + 1);
            self.draw_horizontal_line(rect.x0, x1, bottom, color);
            self.draw_vertical_line(left, rect.y0, y1, color);
            let right = x1.saturating_sub(offset + 1);
            self.draw_vertical_line(right, rect.y0, y1, color);
        }
    }

    fn draw_horizontal_line(&mut self, x0: u32, x1: u32, y: u32, color: [u8; 4]) {
        if y >= self.height {
            return;
        }
        for x in x0.min(self.width)..x1.min(self.width) {
            self.blend_pixel(x, y, color);
        }
    }

    fn draw_vertical_line(&mut self, x: u32, y0: u32, y1: u32, color: [u8; 4]) {
        if x >= self.width {
            return;
        }
        for y in y0.min(self.height)..y1.min(self.height) {
            self.blend_pixel(x, y, color);
        }
    }

    fn draw_label_badge(&mut self, x: u32, y: u32, label: u32, colors: MarkColors) {
        let label = label.to_string();
        let digit_count = label.chars().filter(|ch| ch.is_ascii_digit()).count() as u32;
        if digit_count == 0 {
            return;
        }
        let scale = 2;
        let padding = 2;
        let digit_width = 3 * scale;
        let digit_height = 5 * scale;
        let spacing = scale;
        let badge_width =
            padding * 2 + digit_count * digit_width + digit_count.saturating_sub(1) * spacing;
        let badge_height = padding * 2 + digit_height;
        self.fill_rect(
            Rect {
                x0: x,
                y0: y,
                x1: x.saturating_add(badge_width),
                y1: y.saturating_add(badge_height),
            },
            colors.badge,
        );

        let mut cursor = x.saturating_add(padding);
        let digit_y = y.saturating_add(padding);
        for ch in label.chars() {
            let Some(bitmap) = digit_bitmap(ch) else {
                continue;
            };
            self.draw_digit(cursor, digit_y, scale, bitmap, colors.text);
            cursor = cursor.saturating_add(digit_width + spacing);
        }
    }

    fn fill_rect(&mut self, rect: Rect, color: [u8; 4]) {
        for y in rect.y0.min(self.height)..rect.y1.min(self.height) {
            for x in rect.x0.min(self.width)..rect.x1.min(self.width) {
                self.blend_pixel(x, y, color);
            }
        }
    }

    fn draw_digit(&mut self, x0: u32, y0: u32, scale: u32, bitmap: [u8; 15], color: [u8; 4]) {
        for row in 0..5 {
            for column in 0..3 {
                if bitmap[row * 3 + column] == 0 {
                    continue;
                }
                let x = x0.saturating_add(column as u32 * scale);
                let y = y0.saturating_add(row as u32 * scale);
                self.fill_rect(
                    Rect {
                        x0: x,
                        y0: y,
                        x1: x.saturating_add(scale),
                        y1: y.saturating_add(scale),
                    },
                    color,
                );
            }
        }
    }

    fn blend_pixel(&mut self, x: u32, y: u32, color: [u8; 4]) {
        let index = ((y as usize * self.width as usize) + x as usize) * 4;
        if index + 3 >= self.pixels.len() {
            return;
        }
        let alpha = u16::from(color[3]);
        let inverse = 255_u16.saturating_sub(alpha);
        for (channel, src) in color.iter().take(3).enumerate() {
            let src = u16::from(*src);
            let dst = u16::from(self.pixels[index + channel]);
            self.pixels[index + channel] = ((src * alpha + dst * inverse + 127) / 255) as u8;
        }
        self.pixels[index + 3] = self.pixels[index + 3].max(color[3]);
    }
}

#[derive(Clone, Copy)]
struct MarkColors {
    badge: [u8; 4],
    text: [u8; 4],
}

fn draw_mark(canvas: &mut RgbaCanvas<'_>, bounds: [f32; 4], label: u32) {
    let x0 = clamp_floor(bounds[0], canvas.width);
    let y0 = clamp_floor(bounds[1], canvas.height);
    let x1 = clamp_ceil(bounds[0] + bounds[2], canvas.width);
    let y1 = clamp_ceil(bounds[1] + bounds[3], canvas.height);
    if x1 <= x0 || y1 <= y0 {
        return;
    }

    let border = [255, 42, 42, 255];
    let colors = MarkColors {
        badge: [255, 42, 42, 230],
        text: [255, 255, 255, 255],
    };
    canvas.draw_rect_outline(Rect { x0, y0, x1, y1 }, 2, border);
    canvas.draw_label_badge(x0, y0, label, colors);
}

fn clamp_floor(value: f32, upper: u32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.floor().min(upper as f32) as u32
    }
}

fn clamp_ceil(value: f32, upper: u32) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.ceil().min(upper as f32) as u32
    }
}

fn digit_bitmap(ch: char) -> Option<[u8; 15]> {
    match ch {
        '0' => Some([1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1]),
        '1' => Some([0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1]),
        '2' => Some([1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1]),
        '3' => Some([1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        '4' => Some([1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1]),
        '5' => Some([1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        '6' => Some([1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1]),
        '7' => Some([1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0]),
        '8' => Some([1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1]),
        '9' => Some([1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1]),
        _ => None,
    }
}

fn span_text(spans: &[TaintSpan]) -> String {
    let mut out = String::new();
    for span in spans {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&span.text);
    }
    out
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_span(text: &str) -> TaintSpan {
        TaintSpan {
            provenance: Provenance::Page,
            text: text.into(),
        }
    }

    fn user_span(text: &str) -> TaintSpan {
        TaintSpan {
            provenance: Provenance::User,
            text: text.into(),
        }
    }

    fn checkout_fixture() -> ObservationInput {
        ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("button", "Pay now")
                    .source_id("ax:pay")
                    .stable_hint("button#pay")
                    .bounds([320.0, 700.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email")
                    .source_id("ax:email")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([120.0, 180.0, 360.0, 38.0]),
                RawElement::new("link", "Terms")
                    .source_id("ax:terms")
                    .stable_hint("a[href=/terms]")
                    .bounds([80.0, 760.0, 80.0, 22.0]),
            ],
        )
    }

    #[test]
    fn compiles_schema_observation_with_page_taint() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(checkout_fixture());

        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        assert_eq!(observation.url, "https://shop.example/checkout");
        assert_eq!(observation.seq, 1);
        assert_eq!(observation.elements.len(), 3);
        assert!(observation
            .elements
            .iter()
            .all(|element| element.name.iter().all(TaintSpan::is_tainted)));
        assert_eq!(observation.marks.len(), 3);
    }

    #[test]
    fn stable_ids_survive_relayout_rerender_and_reorder() {
        let mut compiler = ObservationCompiler::new();
        let first = compiler.compile(checkout_fixture());

        let second = compiler.compile(ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("link", "Terms")
                    .source_id("new-terms-source")
                    .stable_hint("a[href=/terms]")
                    .bounds([88.0, 780.0, 80.0, 22.0]),
                RawElement::new("button", "Pay now")
                    .source_id("new-pay-source")
                    .stable_hint("button#pay")
                    .bounds([340.0, 720.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email")
                    .source_id("new-email-source")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([122.0, 185.0, 360.0, 38.0]),
            ],
        ));

        for first_element in &first.elements {
            let matching = second
                .elements
                .iter()
                .find(|candidate| candidate.role == first_element.role);
            assert!(
                matching
                    .map(|candidate| candidate.node_id == first_element.node_id)
                    .unwrap_or(false),
                "{first_element:?}"
            );
        }
    }

    #[test]
    fn ranker_prioritizes_form_controls_and_usable_labels() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(ObservationInput::new(
            "https://example.test",
            vec![
                RawElement::new("generic", "").stable_hint("generic"),
                RawElement::new("button", "Continue").stable_hint("continue"),
                RawElement::new("textbox", "Search")
                    .stable_hint("search")
                    .bounds([0.0, 0.0, 300.0, 32.0]),
            ],
        ));

        assert_eq!(observation.elements[0].role, "textbox");
        assert!(observation.elements[0].rank > observation.elements[1].rank);
        assert!(observation.elements[1].rank > observation.elements[2].rank);
    }

    #[test]
    fn diff_reports_only_added_removed_and_changed_elements() {
        let mut compiler = ObservationCompiler::new();
        let previous = compiler.compile(checkout_fixture());
        let current = compiler.compile(ObservationInput::new(
            "https://shop.example/checkout",
            vec![
                RawElement::new("button", "Pay now")
                    .source_id("ax:pay")
                    .stable_hint("button#pay")
                    .bounds([320.0, 700.0, 180.0, 42.0]),
                RawElement::new("textbox", "Email address")
                    .source_id("ax:email")
                    .stable_hint("input[name=email]")
                    .value("me@example.com")
                    .bounds([120.0, 180.0, 360.0, 38.0]),
                RawElement::new("button", "Apply coupon")
                    .source_id("ax:coupon")
                    .stable_hint("button#coupon")
                    .bounds([120.0, 240.0, 140.0, 38.0]),
            ],
        ));

        let diff = diff_observations(&previous, &current);

        assert_eq!(diff.since_seq, previous.seq);
        assert_eq!(diff.seq, current.seq);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name[0].text, "Apply coupon");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].name[0].text, "Email address");
    }

    #[test]
    fn budgeter_keeps_high_ranked_elements_under_limit() {
        let mut elements = Vec::new();
        for index in 0..80 {
            elements.push(
                RawElement::new("link", format!("Secondary navigation item {index}"))
                    .stable_hint(format!("nav-{index}"))
                    .bounds([0.0, index as f32, 120.0, 24.0]),
            );
        }
        elements.push(
            RawElement::new("textbox", "Search entire catalog")
                .stable_hint("search")
                .bounds([0.0, 0.0, 420.0, 36.0]),
        );

        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: 1_200,
            max_tokens: 400,
            max_marks: 4,
        });
        let observation = compiler.compile(ObservationInput::new("https://example.test", elements));

        assert!(
            serialized_len(&observation) <= 1_200,
            "{}",
            serialized_len(&observation)
        );
        assert!(estimated_tokens(&observation) <= 400);
        assert_eq!(observation.elements[0].role, "textbox");
        assert!(observation.elements.len() < 81);
        assert_eq!(observation.marks.len(), 4.min(observation.elements.len()));
    }

    #[test]
    fn fixture_corpus_stays_inside_default_budget() {
        let fixtures = vec![
            checkout_fixture(),
            ObservationInput::new(
                "https://mail.example/inbox",
                (0..18)
                    .map(|index| {
                        RawElement::new("button", format!("Archive message {index}"))
                            .stable_hint(format!("archive-{index}"))
                            .bounds([20.0, 40.0 + index as f32 * 28.0, 120.0, 24.0])
                    })
                    .collect(),
            ),
            ObservationInput::new(
                "https://docs.example",
                vec![
                    RawElement::new("textbox", "Search docs").stable_hint("docs-search"),
                    RawElement::new("link", "API Reference").stable_hint("api-reference"),
                    RawElement::new("button", "Copy install command").stable_hint("copy-install"),
                ],
            ),
        ];

        let mut compiler = ObservationCompiler::new();
        for fixture in fixtures {
            let observation = compiler.compile(fixture);
            assert!(serialized_len(&observation) <= DEFAULT_MAX_BYTES);
            assert!(estimated_tokens(&observation) <= DEFAULT_MAX_TOKENS);
        }
    }

    #[test]
    fn preserves_non_page_provenance_from_inputs() {
        let mut compiler = ObservationCompiler::new();
        let observation = compiler.compile(ObservationInput::new(
            "https://example.test",
            vec![RawElement::new("textbox", "Task")
                .stable_hint("task")
                .name_spans(vec![user_span("Find invoices")])
                .value_spans(vec![page_span("Invoice table")])],
        ));

        assert_eq!(observation.elements[0].name[0].provenance, Provenance::User);
        assert_eq!(
            observation.elements[0].value[0].provenance,
            Provenance::Page
        );
    }

    #[test]
    fn set_of_marks_compositor_draws_bounds_and_label_pixels() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 2,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![
                RawElement::new("button", "Continue")
                    .stable_hint("continue")
                    .bounds([10.0, 8.0, 22.0, 16.0]),
                RawElement::new("link", "Help")
                    .stable_hint("help")
                    .bounds([40.0, 20.0, 10.0, 10.0]),
            ],
        ));
        let input = solid_rgba(64, 48, [240, 240, 240, 255]);

        let output = composite_set_of_marks_rgba(&input, 64, 48, &observation)?;

        assert_ne!(output, input);
        assert_eq!(pixel_rgba(&input, 64, 1, 1)?, [240, 240, 240, 255]);
        assert_eq!(pixel_rgba(&output, 64, 1, 1)?, [240, 240, 240, 255]);
        let border = pixel_rgba(&output, 64, 10, 8)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        let badge = pixel_rgba(&output, 64, 11, 9)?;
        assert!(badge[0] > 245);
        assert!(badge[1] < 100);
        assert!(badge[2] < 100);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_clips_bounds_to_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("button", "Partly visible")
                .stable_hint("partial")
                .bounds([-4.0, -3.0, 12.0, 10.0])],
        ));
        let input = solid_rgba(24, 16, [20, 20, 20, 255]);

        let output = composite_set_of_marks_rgba(&input, 24, 16, &observation)?;

        let top_left = pixel_rgba(&output, 24, 0, 0)?;
        assert!(top_left[0] > 150);
        assert!(top_left[1] < 80);
        assert!(top_left[2] < 80);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_rejects_invalid_rgba_buffer() {
        let observation = CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: "https://marks.test".into(),
            seq: 1,
            elements: Vec::new(),
            marks: Vec::new(),
        };

        let error = composite_set_of_marks_rgba(&[0, 1, 2], 8, 8, &observation);

        assert!(matches!(
            error,
            Err(MarkCompositorError::InvalidBufferLength {
                expected: 256,
                actual: 3
            })
        ));
    }

    #[test]
    fn set_of_marks_compositor_overlays_png_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("button", "Continue")
                .stable_hint("continue")
                .bounds([4.0, 3.0, 12.0, 8.0])],
        ));
        let input = solid_rgba(32, 24, [12, 34, 56, 255]);
        let input_png = encode_rgba_png(&input, 32, 24)?;

        let output_png = composite_set_of_marks_png(&input_png, &observation)?;
        let decoded = decode_png_to_rgba(&output_png)?;

        assert_eq!(decoded.width, 32);
        assert_eq!(decoded.height, 24);
        assert_eq!(pixel_rgba(&decoded.rgba, 32, 31, 23)?, [12, 34, 56, 255]);
        let border = pixel_rgba(&decoded.rgba, 32, 4, 3)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        Ok(())
    }

    #[test]
    fn set_of_marks_compositor_accepts_rgb_png_screenshot() -> Result<(), MarkCompositorError> {
        let mut compiler = ObservationCompiler::with_options(CompileOptions {
            max_bytes: DEFAULT_MAX_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_marks: 1,
        });
        let observation = compiler.compile(ObservationInput::new(
            "https://marks.test",
            vec![RawElement::new("link", "Details")
                .stable_hint("details")
                .bounds([6.0, 5.0, 10.0, 8.0])],
        ));
        let input_png = encode_rgb_png(&solid_rgb(24, 18, [90, 100, 110]), 24, 18)?;

        let output_png = composite_set_of_marks_png(&input_png, &observation)?;
        let decoded = decode_png_to_rgba(&output_png)?;

        assert_eq!(pixel_rgba(&decoded.rgba, 24, 23, 17)?, [90, 100, 110, 255]);
        let border = pixel_rgba(&decoded.rgba, 24, 6, 5)?;
        assert!(border[0] > 245);
        assert!(border[1] < 80);
        assert!(border[2] < 80);
        Ok(())
    }

    fn solid_rgba(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity((width as usize) * (height as usize) * 4);
        for _ in 0..(width as usize * height as usize) {
            pixels.extend_from_slice(&color);
        }
        pixels
    }

    fn solid_rgb(width: u32, height: u32, color: [u8; 3]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity((width as usize) * (height as usize) * 3);
        for _ in 0..(width as usize * height as usize) {
            pixels.extend_from_slice(&color);
        }
        pixels
    }

    fn encode_rgb_png(rgb: &[u8], width: u32, height: u32) -> Result<Vec<u8>, MarkCompositorError> {
        let expected = (width as usize) * (height as usize) * 3;
        if rgb.len() != expected {
            return Err(MarkCompositorError::InvalidBufferLength {
                expected,
                actual: rgb.len(),
            });
        }

        let mut output = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut output, width, height);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder
                .write_header()
                .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
            writer
                .write_image_data(rgb)
                .map_err(|error| MarkCompositorError::PngEncode(error.to_string()))?;
        }
        Ok(output)
    }

    fn pixel_rgba(
        pixels: &[u8],
        width: u32,
        x: u32,
        y: u32,
    ) -> Result<[u8; 4], MarkCompositorError> {
        let index = ((y as usize * width as usize) + x as usize) * 4;
        if index + 3 >= pixels.len() {
            return Err(MarkCompositorError::InvalidBufferLength {
                expected: index + 4,
                actual: pixels.len(),
            });
        }
        Ok([
            pixels[index],
            pixels[index + 1],
            pixels[index + 2],
            pixels[index + 3],
        ])
    }
}
