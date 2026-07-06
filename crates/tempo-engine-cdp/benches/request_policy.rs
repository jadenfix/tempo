use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempo_engine_cdp::{request_policy_wait_bench_once, RequestPolicyWaitBenchCase};
use tokio::runtime::{Builder, Runtime};

fn runtime() -> Runtime {
    match Builder::new_current_thread().enable_time().build() {
        Ok(runtime) => runtime,
        Err(error) => panic!("failed to build benchmark runtime: {error}"),
    }
}

fn wait_once(runtime: &Runtime, case: RequestPolicyWaitBenchCase) -> Duration {
    match runtime.block_on(request_policy_wait_bench_once(case)) {
        Ok(elapsed) => elapsed,
        Err(error) => panic!("request-policy wait benchmark failed: {error}"),
    }
}

fn bench_request_policy_wait(c: &mut Criterion) {
    let runtime = runtime();
    let mut group = c.benchmark_group("cdp/request-policy-wait");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(2));

    group.bench_function("idle-no-observed-request", |b| {
        b.iter(|| {
            black_box(wait_once(
                &runtime,
                RequestPolicyWaitBenchCase::IdleNoObservedRequest,
            ))
        });
    });
    group.bench_function("observed-clean-request-grace", |b| {
        b.iter(|| {
            black_box(wait_once(
                &runtime,
                RequestPolicyWaitBenchCase::ObservedCleanRequest,
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_request_policy_wait);
criterion_main!(benches);
