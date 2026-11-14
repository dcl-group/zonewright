//! Page loops with a hard page limit (design section 5.4).
//!
//! A listing follows cursors, page numbers and tokens only; a URL returned by the provider is
//! never requested. A listing that would need more than [`MAX_PAGES`] pages fails with
//! `Error::Protocol` instead of being returned in part.

use std::future::Future;

use crate::error::Error;
use crate::redact::Detail;

/// Most pages one listing reads.
pub(crate) const MAX_PAGES: u32 = 1000;

/// One page of a listing: its items and the cursor of the next page, `None` on the last page.
#[derive(Debug)]
pub(crate) struct Page<T, C> {
    /// The items of this page.
    pub(crate) items: Vec<T>,
    /// The cursor of the next page.
    pub(crate) next: Option<C>,
}

/// Reads every page of a listing, starting at `first`, and returns all items in order.
///
/// `fetch` reads the page at a cursor. The cursor type is the provider's: a page number, an
/// offset, a token, or a compound (Route 53's next name and type). The helpers below compute the
/// next cursor for the styles in use. A next cursor equal to the current one is a provider that
/// does not advance, and `Error::Protocol`.
pub(crate) async fn collect<T, C, F, Fut>(first: C, mut fetch: F) -> Result<Vec<T>, Error>
where
    C: Clone + PartialEq,
    F: FnMut(C) -> Fut,
    Fut: Future<Output = Result<Page<T, C>, Error>>,
{
    let mut items = Vec::new();
    let mut cursor = first;
    for _ in 0..MAX_PAGES {
        let page = fetch(cursor.clone()).await?;
        items.extend(page.items);
        match page.next {
            None => return Ok(items),
            Some(next) if next == cursor => {
                return Err(Error::Protocol {
                    detail: Detail::constant("the provider's pagination did not advance"),
                });
            }
            Some(next) => cursor = next,
        }
    }
    Err(Error::Protocol {
        detail: Detail::constant("the listing has more than 1000 pages, the limit of the client"),
    })
}

/// Page number with a total page count (pages counted from 1): the next page, if any.
pub(crate) fn next_page_of_total(page: u32, total_pages: u32) -> Option<u32> {
    (page < total_pages).then(|| page.saturating_add(1))
}

/// A page token, where an absent or empty token means the last page.
pub(crate) fn next_token(token: Option<String>) -> Option<String> {
    token.filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::error::ErrorKind;

    #[tokio::test]
    async fn pages_are_read_until_the_last() {
        let calls = AtomicU32::new(0);
        let items = collect(1u32, |page| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok(Page {
                    items: vec![page * 10, page * 10 + 1],
                    next: next_page_of_total(page, 3),
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(items, [10, 11, 20, 21, 30, 31]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn the_page_limit_is_an_error() {
        let calls = AtomicU32::new(0);
        let e = collect(0u64, |offset| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok(Page {
                    items: vec![offset],
                    next: Some(offset + 1),
                })
            }
        })
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        assert!(e.to_string().contains("1000 pages"), "{e}");
        assert_eq!(calls.load(Ordering::SeqCst), MAX_PAGES);
    }

    #[tokio::test]
    async fn a_cursor_that_does_not_advance_is_an_error() {
        let e = collect("t".to_owned(), |token| async move {
            Ok(Page::<u8, String> {
                items: Vec::new(),
                next: Some(token),
            })
        })
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
        let e = collect(1u32, |page| async move {
            Err::<Page<u8, u32>, _>(Error::transient(&format!("page {page}")))
        })
        .await
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient);
    }

    #[test]
    fn next_cursor_helpers() {
        assert_eq!(next_page_of_total(1, 3), Some(2));
        assert_eq!(next_page_of_total(3, 3), None);
        assert_eq!(next_page_of_total(1, 0), None);
        assert_eq!(next_token(Some("abc".to_owned())).as_deref(), Some("abc"));
        assert_eq!(next_token(Some(String::new())), None);
        assert_eq!(next_token(None), None);
    }
}
