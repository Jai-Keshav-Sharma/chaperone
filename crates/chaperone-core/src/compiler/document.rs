//! DocumentParser (flows/01 ingestion): SOP text from the supported formats.
//!
//! Local-first: .md/.txt/.html are parsed with no heavy dependencies; .docx
//! (a zip) and .pdf text are best-effort local extractions. OCR tiers are a
//! documented roadmap extension — the trait keeps them pluggable without ever
//! hard-coding a provider.

/// The parsed result: plain text SOP content.
pub struct ParsedDocument {
    pub text: String,
    /// The source format (provenance/observability).
    pub format: DocumentFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFormat {
    Markdown,
    PlainText,
    Pdf,
    Docx,
    Html,
}

/// The ingestion seam. Local-first by default; OCR/cloud tiers plug in here.
pub trait DocumentParser: Send + Sync {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String>;
}

/// A parser selected by file extension. Dispatches to the format-specific
/// implementation.
pub struct ExtensionParser;

impl ExtensionParser {
    pub fn for_path(path: &str) -> Box<dyn DocumentParser> {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "md" | "markdown" => Box::new(MarkdownParser),
            "txt" => Box::new(TextParser),
            "pdf" => Box::new(PdfParser),
            "docx" => Box::new(DocxParser),
            "html" | "htm" => Box::new(HtmlParser),
            _ => Box::new(TextParser), // unknown → treat as text
        }
    }
}

/// .md — plain text (markdown passes through verbatim; the LLM reads it).
pub struct MarkdownParser;

impl DocumentParser for MarkdownParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String> {
        let text = String::from_utf8_lossy(bytes).to_string();
        Ok(ParsedDocument {
            text,
            format: DocumentFormat::Markdown,
        })
    }
}

/// .txt — plain text.
pub struct TextParser;

impl DocumentParser for TextParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String> {
        let text = String::from_utf8_lossy(bytes).to_string();
        Ok(ParsedDocument {
            text,
            format: DocumentFormat::PlainText,
        })
    }
}

/// .html — strip tags (a small, dependency-free scrape of text content).
pub struct HtmlParser;

impl DocumentParser for HtmlParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String> {
        let html = String::from_utf8_lossy(bytes).to_string();
        Ok(ParsedDocument {
            text: strip_html(&html),
            format: DocumentFormat::Html,
        })
    }
}

fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '<' {
            let rest = &html[i..];
            if rest.starts_with("<script") {
                in_script = true;
            } else if rest.starts_with("</script") {
                in_script = false;
            } else if rest.starts_with("<style") {
                in_style = true;
            } else if rest.starts_with("</style") {
                in_style = false;
            }
            in_tag = true;
            i += 1;
            continue;
        }
        if c == '>' {
            in_tag = false;
            i += 1;
            continue;
        }
        if !in_tag && !in_script && !in_style {
            out.push(c);
        }
        i += 1;
    }
    // Collapse runs of whitespace and trim.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// .pdf — best-effort digital text extraction. The PDF text layer is not
/// trivially decodable without a crate, so this local-first parser extracts
/// ASCII runs from the raw bytes (usable for simple digital PDFs). Scanned
/// PDFs need an OCR tier (documented roadmap; the trait is the plug point).
pub struct PdfParser;

impl DocumentParser for PdfParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String> {
        if bytes.len() < 4 || &bytes[0..4] != b"%PDF" {
            return Err("not a PDF (missing %PDF header)".to_string());
        }
        // Extract printable runs between stream/endstream as a best-effort text
        // layer. This is honest-local extraction, not a full PDF parser.
        let mut text = String::new();
        let mut i = 0;
        while i + 6 <= bytes.len() {
            if &bytes[i..i + 6] == b"stream" {
                let start = i + 6;
                if bytes[start..].starts_with(b"\r\n") {
                    i = start + 2;
                } else if bytes[start..].starts_with(b"\n") {
                    i = start + 1;
                } else {
                    i = start;
                }
                // Read until endstream.
                let mut run = String::new();
                while i + 9 <= bytes.len() && &bytes[i..i + 9] != b"endstream" {
                    let b = bytes[i];
                    if (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                        run.push(b as char);
                    }
                    i += 1;
                }
                text.push_str(&run);
                text.push('\n');
                continue;
            }
            i += 1;
        }
        if text.trim().is_empty() {
            return Err("no extractable PDF text layer (scanned PDF needs OCR)".to_string());
        }
        Ok(ParsedDocument {
            text: text.split_whitespace().collect::<Vec<_>>().join(" "),
            format: DocumentFormat::Pdf,
        })
    }
}

/// .docx — a zip archive; the document text is in `word/document.xml`. A
/// minimal local extraction reads the XML text content without a zip crate.
pub struct DocxParser;

impl DocumentParser for DocxParser {
    fn parse(&self, bytes: &[u8]) -> Result<ParsedDocument, String> {
        if bytes.len() < 2 || &bytes[0..2] != b"PK" {
            return Err("not a docx (missing ZIP header)".to_string());
        }
        // Extract the text between <w:t> XML tags (a docx's visible text lives
        // there). Best-effort: no zip decompression, so it works on the
        // document.xml stream only when present in a simple archive.
        let s = String::from_utf8_lossy(bytes);
        let mut text = String::new();
        let mut rest = s.as_ref();
        while let Some(start) = rest.find("<w:t") {
            let after = &rest[start..];
            let Some(gt) = after.find('>') else { break };
            let content_start = start + gt + 1;
            let Some(end) = after[gt..].find("</w:t>") else {
                break;
            };
            let content_end = content_start + end - gt;
            text.push_str(&rest[content_start..content_end]);
            rest = &rest[content_end..];
        }
        if text.trim().is_empty() {
            return Err(
                "no extractable docx text (compressed stream needs zip decoding)".to_string(),
            );
        }
        Ok(ParsedDocument {
            text: text.split_whitespace().collect::<Vec<_>>().join(" "),
            format: DocumentFormat::Docx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_strips_tags_and_scripts() {
        let html = r#"<html><head><style>.x{}</style><script>alert(1)</script></head><body><h1>Refunds</h1><p>Up to $200 allowed.</p></body></html>"#;
        let doc = HtmlParser.parse(html.as_bytes()).expect("parse");
        assert!(doc.text.contains("Refunds"));
        assert!(doc.text.contains("Up to $200 allowed."));
        assert!(!doc.text.contains("alert"), "script removed");
    }

    #[test]
    fn pdf_rejects_non_pdf() {
        assert!(PdfParser.parse(b"not a pdf").is_err());
    }

    #[test]
    fn docx_rejects_non_zip() {
        assert!(DocxParser.parse(b"not a zip").is_err());
    }

    #[test]
    fn text_and_markdown_pass_through() {
        assert_eq!(TextParser.parse(b"hello").unwrap().text, "hello");
        assert_eq!(MarkdownParser.parse(b"# Title").unwrap().text, "# Title");
    }

    #[test]
    fn extension_parser_dispatches() {
        assert_eq!(
            ExtensionParser::for_path("a.md")
                .parse(b"x")
                .unwrap()
                .format,
            DocumentFormat::Markdown
        );
        assert_eq!(
            ExtensionParser::for_path("a.html")
                .parse(b"<p>x</p>")
                .unwrap()
                .format,
            DocumentFormat::Html
        );
        assert_eq!(
            ExtensionParser::for_path("a.txt")
                .parse(b"x")
                .unwrap()
                .format,
            DocumentFormat::PlainText
        );
    }
}
