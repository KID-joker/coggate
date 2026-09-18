package io.github.kidjoker.coggate;

/** Closed V1 verification-attempt budget. */
public enum AttemptLimit {
  ONE(1),
  TWO(2);

  private final int value;

  AttemptLimit(int value) {
    this.value = value;
  }

  public int value() {
    return value;
  }
}
