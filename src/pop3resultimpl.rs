use pop3result::{POP3Stat, POP3List, EmailMetadata};
use regex::Regex;


lazy_static! {
    static ref STAT_REGEX: Regex = Regex::new(r"(?P<nmsg>\d+) (?P<size>\d+)").unwrap();
    static ref LIST_HEADER_REGEX: Regex = Regex::new(r"(\+OK|\-ERR) (?P<nmsg>\d+) [a-z ]+ \((?P<size>\d+) [a-z]+\)").unwrap();
}

impl POP3Stat {
    pub fn parse(stat_line: &str) -> POP3Stat {
        let stat_cap = STAT_REGEX.captures(stat_line).unwrap();
        POP3Stat {
            num_mails: stat_cap.name("nmsg").unwrap().as_str().parse::<u32>().unwrap(),
            mbox_size: stat_cap.name("size").unwrap().as_str().parse::<u32>().unwrap(),
        }
    }
}

impl POP3List {
    pub fn parse(list_data: &[String]) -> POP3List {
        let mut mbox: Vec<EmailMetadata> = Vec::new();
        // Parse the first line of the LIST response
        let cap = LIST_HEADER_REGEX.captures(list_data[0].as_ref()).unwrap();
        let mbox_stat = POP3Stat {
            num_mails: cap.name("nmsg").unwrap().as_str().parse::<u32>().unwrap(),
            mbox_size: cap.name("size").unwrap().as_str().parse::<u32>().unwrap(),
        };
        // Parse all the other lines that contain details
        for line in list_data[1..].iter() {
            let cap = STAT_REGEX.captures(line).unwrap();
            mbox.push(EmailMetadata {
                msg_id: cap.name("nmsg").unwrap().as_str().parse::<u32>().unwrap(),
                msg_size: cap.name("size").unwrap().as_str().parse::<u32>().unwrap()
            })
        }
        POP3List { mailbox: mbox, mbox_stat: mbox_stat }
    }
}
