use std::str::CharIndices;

pub struct SplitQuoted<'a> {
    s: &'a str,
    pos: CharIndices<'a>,
}

impl<'a> Iterator for SplitQuoted<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        let mut start;
        let quote_char: char;
        loop {
            if let Some((i, c)) = self.pos.next() {
                if !c.is_whitespace() {
                    start = i;
                    quote_char = c;
                    break;
                }
            } else {
                return None;
            }
        }
        let end: usize;
        if quote_char == '"' || quote_char == '\'' {
            start += 1;
            loop {
                if let Some((i, c)) = self.pos.next() {
                    if c == quote_char {
                        end = i;
                        break;
                    }
                } else {
                    end = self.s.len();
                    break;
                }
            }
        } else {
            loop {
                if let Some((i, c)) = self.pos.next() {
                    if c.is_whitespace() {
                        end = i;
                        break;
                    }
                } else {
                    end = self.s.len();
                    break;
                }
            }
        }

        Some(&self.s[start..end])
    }
}

pub fn split_quoted(s: &str) -> SplitQuoted {
    SplitQuoted {
        s,
        pos: s.char_indices(),
    }
}

#[test]
fn test_split_quoted() {
    let mut split = split_quoted("  dashk\tjöasjkl \"jh  \thjk\'hjkk\" sd");
    assert_eq!(split.next(), Some("dashk"));
    assert_eq!(split.next(), Some("jöasjkl"));
    assert_eq!(split.next(), Some("jh  \thjk'hjkk"));
    assert_eq!(split.next(), Some("sd"));
    assert_eq!(split.next(), None);

    let mut split = split_quoted("  'dashk\" \"sh ' 12 \"kjsdk ");
    assert_eq!(split.next(), Some("dashk\" \"sh "));
    assert_eq!(split.next(), Some("12"));
    assert_eq!(split.next(), Some("kjsdk "));
    assert_eq!(split.next(), None);

    let mut split = split_quoted("  \t\n");
    assert_eq!(split.next(), None);
}
