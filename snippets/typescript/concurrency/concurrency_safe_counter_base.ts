// CONCURRENCY ISSUES
// Prevents multiple async operations from stomping on each other.
// Uses a promise-chain so only one caller can modify
// shared state at a time — everyone else waits their turn.

class SafeCounter {
  private lock: Promise<void> = Promise.resolve();
  private count = 0;

  async increment(): Promise<number> {
    let release: () => void;
    const acquired = new Promise<void>((res) => (release = res));
    const prev = this.lock;
    this.lock = acquired;

    await prev;
    try {
      this.count += 1;
      return this.count;
    } finally {
      release!();
    }
  }
}
