//! Go's `text/tabwriter` with a space as the padding character and no flags (`tabwriter.NewWriter(w, minwidth, tabwidth,
//! padding, ' ', 0)`), which is how the Go commands print tables: cells end at a tab, a column is as wide as its widest cell
//! (counted in characters) plus the padding and at least `minwidth`, and a column block ends at a line with fewer cells,
//! exactly as Go's `format` walks them. The text after a line's last tab is not part of any column.

/// One table, written whole by `flush`.
pub struct TabWriter {
    minwidth: usize,
    padding: usize,
    text: String,
}

#[derive(Clone)]
struct Cell {
    text: String,
    width: usize,
}

impl TabWriter {
    /// `tabwriter.NewWriter(w, minwidth, tabwidth, padding, ' ', 0)`; the tab width only matters when padding with tabs.
    pub fn new(minwidth: usize, _tabwidth: usize, padding: usize) -> TabWriter {
        TabWriter { minwidth, padding, text: String::new() }
    }

    pub fn write(&mut self, s: &str) {
        self.text.push_str(s);
    }

    /// The table as Go's `Flush` writes it.
    pub fn flush(&mut self) -> String {
        let text = std::mem::take(&mut self.text);
        // lines of cells; a line's last cell is the text after its last tab (possibly empty)
        let mut lines: Vec<Vec<Cell>> = Vec::new();
        let mut cur: Vec<Cell> = Vec::new();
        let mut cell = String::new();
        let ends_with_newline = text.ends_with('\n');
        for c in text.chars() {
            match c {
                '\t' | '\x0b' => {
                    let w = cell.chars().count();
                    cur.push(Cell { text: std::mem::take(&mut cell), width: w });
                }
                '\n' | '\x0c' => {
                    let w = cell.chars().count();
                    cur.push(Cell { text: std::mem::take(&mut cell), width: w });
                    lines.push(std::mem::take(&mut cur));
                }
                _ => cell.push(c),
            }
        }
        // the unfinished last line (Go keeps it as the last buffered line, written without a newline)
        let w = cell.chars().count();
        cur.push(Cell { text: cell, width: w });
        lines.push(cur);
        let mut out = String::new();
        let mut widths: Vec<usize> = Vec::new();
        self.format(&mut out, &lines, &mut widths, 0, lines.len());
        // Go writes a newline after every line but the last buffered one; text ending in a newline leaves an empty last line
        let _ = ends_with_newline;
        out
    }

    fn format(&self, out: &mut String, lines: &[Vec<Cell>], widths: &mut Vec<usize>, line0: usize, line1: usize) {
        let mut line0 = line0;
        let column = widths.len();
        let mut this = line0;
        while this < line1 {
            if column + 1 >= lines[this].len() {
                this += 1;
                continue;
            }
            // a cell in this column: print what came before the block, then find the block's width
            self.write_lines(out, lines, widths, line0, this);
            line0 = this;
            let mut width = self.minwidth;
            while this < line1 {
                let line = &lines[this];
                if column + 1 >= line.len() {
                    break;
                }
                width = width.max(line[column].width + self.padding);
                this += 1;
            }
            widths.push(width);
            self.format(out, lines, widths, line0, this);
            widths.pop();
            line0 = this;
        }
        self.write_lines(out, lines, widths, line0, line1);
    }

    fn write_lines(&self, out: &mut String, lines: &[Vec<Cell>], widths: &[usize], line0: usize, line1: usize) {
        for (i, line) in lines.iter().enumerate().take(line1).skip(line0) {
            for (j, c) in line.iter().enumerate() {
                out.push_str(&c.text);
                if j < widths.len() {
                    for _ in c.width..widths[j] {
                        out.push(' ');
                    }
                }
            }
            if i + 1 < lines.len() {
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_go_writes_a_table() {
        // from Go: tabwriter.NewWriter(&b, 2, 4, 2, ' ', 0), these lines, Flush
        let mut tw = TabWriter::new(2, 4, 2);
        tw.write("  IP\tNAME\tMAKER\n");
        tw.write("  192.0.2.1\trouter\tAcme\n");
        tw.write("  192.0.2.10\tTV ünï\t\n");
        assert_eq!(tw.flush(), "  IP          NAME    MAKER\n  192.0.2.1   router  Acme\n  192.0.2.10  TV ünï  \n");
        let mut tw = TabWriter::new(2, 4, 2);
        tw.write("a\tb\n");
        tw.write("no tabs here\n");
        tw.write("ccc\td\n");
        assert_eq!(tw.flush(), "a  b\nno tabs here\nccc  d\n");
        let mut tw = TabWriter::new(2, 4, 2);
        tw.write("x\ty\tz");
        assert_eq!(tw.flush(), "x  y  z");
    }
}
