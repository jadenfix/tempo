//! Benchmarks for the policy gate. Every action in every batch passes through
//! origin parsing + rule matching before execution, so this is fixed per-action
//! overhead on the act path.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tempo_policy::{InputTaint, Origin, OriginPolicy, OriginRule, OriginRuleMode};
use tempo_schema::SideEffect;

fn policy_with_rules(origins: usize) -> OriginPolicy {
    let rules = (0..origins)
        .map(|index| {
            let origin = Origin::parse(&format!("https://site-{index}.example.com")).unwrap();
            let mode = match index % 3 {
                0 => OriginRuleMode::RequireConfirmation,
                1 => OriginRuleMode::RequireTaintReview,
                _ => OriginRuleMode::Block,
            };
            OriginRule::new(origin, SideEffect::Write, mode)
        })
        .collect();
    OriginPolicy::new(rules)
}

fn bench_origin_parse(c: &mut Criterion) {
    c.bench_function("policy/origin-parse", |b| {
        b.iter(|| {
            black_box(Origin::parse(black_box(
                "https://shop.example.com:8443/checkout?step=2",
            )))
        });
    });
}

fn bench_decide_effect(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy/decide-effect");
    for &rules in &[8_usize, 64, 512] {
        let policy = policy_with_rules(rules);
        // Worst case: the matching origin is the last rule inserted.
        let origin = Origin::parse(&format!("https://site-{}.example.com", rules - 1)).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(rules), &policy, |b, policy| {
            b.iter(|| {
                black_box(policy.decide_effect(
                    Some(black_box(&origin)),
                    SideEffect::Send,
                    InputTaint::CLEAN,
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_origin_parse, bench_decide_effect);
criterion_main!(benches);
