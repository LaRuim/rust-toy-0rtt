pub const EARLY_DATA_ACCEPTED: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NoTicket,
    ResumedNoEarly,
    EarlyRejected,
    EarlyAccepted { request_in_0rtt: bool },
}

impl Outcome {
    pub fn classify(
        offered_ticket: bool,
        early_data: bool,
        resumed: bool,
        early_reason: u32,
        request_in_0rtt: bool,
    ) -> Self {
        if offered_ticket && early_data {
            if early_reason == EARLY_DATA_ACCEPTED {
                Outcome::EarlyAccepted { request_in_0rtt }
            } else {
                Outcome::EarlyRejected
            }
        } else if resumed {
            Outcome::ResumedNoEarly
        } else {
            Outcome::NoTicket
        }
    }

    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Outcome::EarlyAccepted {
                request_in_0rtt: false
            }
        )
    }
}
