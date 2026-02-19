//! Connection state machine

use crate::{Error, Result};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state (not connected)
    Initial,

    /// TLS negotiation in progress (SSLRequest sent, awaiting S/N response)
    NegotiatingTls,

    /// Startup sent, awaiting authentication request
    AwaitingAuth,

    /// Authentication in progress
    Authenticating,

    /// Idle (ready for query)
    Idle,

    /// Query in progress
    QueryInProgress,

    /// Reading query results
    ReadingResults,

    /// Closed
    Closed,
}

impl ConnectionState {
    /// Check if transition is valid
    pub fn can_transition_to(&self, next: ConnectionState) -> bool {
        use ConnectionState::*;

        matches!(
            (self, next),
            (Initial, NegotiatingTls)
                | (Initial, AwaitingAuth)
                | (NegotiatingTls, AwaitingAuth)
                | (AwaitingAuth, Authenticating)
                | (Authenticating, Idle)
                | (Idle, QueryInProgress)
                | (QueryInProgress, ReadingResults)
                | (ReadingResults, Idle)
                | (_, Closed)
        )
    }

    /// Transition to new state
    pub fn transition(&mut self, next: ConnectionState) -> Result<()> {
        if !self.can_transition_to(next) {
            return Err(Error::InvalidState {
                expected: format!("valid transition from {:?}", self),
                actual: format!("{:?}", next),
            });
        }
        *self = next;
        Ok(())
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::NegotiatingTls => write!(f, "negotiating_tls"),
            Self::AwaitingAuth => write!(f, "awaiting_auth"),
            Self::Authenticating => write!(f, "authenticating"),
            Self::Idle => write!(f, "idle"),
            Self::QueryInProgress => write!(f, "query_in_progress"),
            Self::ReadingResults => write!(f, "reading_results"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let mut state = ConnectionState::Initial;
        assert!(state.transition(ConnectionState::AwaitingAuth).is_ok());
        assert!(state.transition(ConnectionState::Authenticating).is_ok());
        assert!(state.transition(ConnectionState::Idle).is_ok());
    }

    #[test]
    fn test_invalid_transition() {
        let mut state = ConnectionState::Initial;
        assert!(state.transition(ConnectionState::Idle).is_err());
    }

    #[test]
    fn test_close_from_any_state() {
        let mut state = ConnectionState::QueryInProgress;
        assert!(state.transition(ConnectionState::Closed).is_ok());
    }

    #[test]
    fn test_tls_negotiation_transitions() {
        let mut state = ConnectionState::Initial;
        assert!(state.transition(ConnectionState::NegotiatingTls).is_ok());
        assert!(state.transition(ConnectionState::AwaitingAuth).is_ok());
    }

    #[test]
    fn test_initial_can_skip_tls_negotiation() {
        // When sslmode=disable, we skip NegotiatingTls
        let mut state = ConnectionState::Initial;
        assert!(state.transition(ConnectionState::AwaitingAuth).is_ok());
    }

    #[test]
    fn test_invalid_tls_transition() {
        let mut state = ConnectionState::Idle;
        assert!(state.transition(ConnectionState::NegotiatingTls).is_err());
    }
}
