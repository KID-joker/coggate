#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    AtMost,
    AtLeast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Threshold {
    direction: Direction,
    percent: u8,
}

impl Threshold {
    pub const fn at_most(percent: u8) -> Self {
        Self {
            direction: Direction::AtMost,
            percent,
        }
    }

    pub const fn at_least(percent: u8) -> Self {
        Self {
            direction: Direction::AtLeast,
            percent,
        }
    }

    pub fn evaluate(self, successes: usize, total: usize) -> Result<bool, ThresholdError> {
        if self.percent > 100 || total == 0 || successes > total {
            return Err(ThresholdError::InvalidInputs);
        }
        let left = successes
            .checked_mul(100)
            .ok_or(ThresholdError::ArithmeticOverflow)?;
        let right = total
            .checked_mul(usize::from(self.percent))
            .ok_or(ThresholdError::ArithmeticOverflow)?;
        Ok(match self.direction {
            Direction::AtMost => left <= right,
            Direction::AtLeast => left >= right,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ThresholdError {
    #[error("invalid benchmark threshold inputs")]
    InvalidInputs,
    #[error("benchmark threshold arithmetic overflow")]
    ArithmeticOverflow,
}
