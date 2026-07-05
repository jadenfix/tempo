#!/usr/bin/env bash
set -euo pipefail

# Release-blocking denial sentinels (#332). `cargo test <filter>` succeeds when
# zero tests match, so each sentinel is first checked against libtest's exact
# listing and then executed with the same exact name.
SENTINELS=(
  "tempo-policy|trust::tests::confirmed_claim_never_satisfies_a_gate|confirmed-claim ignored"
  "tempo-policy|trust::tests::caller_clean_claim_cannot_clear_recomputed_taint|clean-claim recompute blocks"
  "tempo-policy|trust::tests::external_write_is_tainted_even_with_clean_server_evidence|forced taint on write"
  "tempo-mcp|tests::act_confirmed_claim_cannot_bypass_gate_without_confirmation_channel|MCP confirmed-claim ignored"
  "tempo-mcp|tests::act_recomputes_taint_from_observation_and_blocks_clean_claim|MCP clean-claim recompute blocks"
  "tempo-mcp|tests::act_denies_unconfirmed_tainted_write_before_driver_execution|MCP no driver dispatch before denial"
  "tempo-headless|tests::session_act_batch_ignores_caller_confirmed_for_external_writes|REST forced taint on external writes"
  "tempo-headless|tests::session_act_batch_goto_recomputes_taint_from_observation_and_blocks_clean_claim|REST clean-claim recompute blocks"
  "tempo-headless|tests::bidi_navigate_recomputes_taint_from_observation_and_blocks_clean_claim|BiDi clean-claim recompute blocks"
  "tempo-headless|tests::bidi_endpoint_denies_client_claimed_clean_script_without_confirmation_channel|BiDi forced taint on script"
  "tempo-headless|tests::bidi_endpoint_denies_unconfirmed_tainted_script_before_driver_execution|BiDi no driver IPC before script denial"
  "tempo-agent|decider::tests::decided_goto_recomputes_page_text_taint_and_denies_before_driver_execution|decided loop no driver execution before denial"
)

for sentinel in "${SENTINELS[@]}"; do
  IFS='|' read -r package test_name purpose <<< "$sentinel"
  printf 'checking denial sentinel (%s): %s %s\n' "$purpose" "$package" "$test_name"

  list_output="$(cargo test -p "$package" --lib "$test_name" -- --exact --list)"
  if ! grep -Fqx "$test_name: test" <<< "$list_output"; then
    printf 'missing exact denial sentinel: %s %s\n' "$package" "$test_name" >&2
    printf '%s\n' "$list_output" >&2
    exit 1
  fi

  cargo test -p "$package" --lib "$test_name" -- --exact
done
