package fetch

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type HTTPFetcher struct{}

func (f *HTTPFetcher) FetchPage(ctx context.Context, rawURL, mode string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Potpuri/1.0 (+https://potpuri.cc)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}

	doc, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}

	switch mode {
	case "meta":
		return extractMeta(doc), nil
	case "full":
		return extractFull(doc), nil
	default:
		return "", nil
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func extractMeta(doc *html.Node) string {
	var title, desc string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					title = strings.TrimSpace(n.FirstChild.Data)
				}
				return
			case "meta":
				name := strings.ToLower(attr(n, "name"))
				prop := strings.ToLower(attr(n, "property"))
				content := attr(n, "content")
				if (name == "description" || prop == "og:description") && desc == "" {
					desc = content
				}
			case "script", "style":
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var parts []string
	if desc != "" {
		parts = append(parts, desc)
	}
	if title != "" && desc == "" {
		parts = append(parts, title)
	}
	return strings.Join(parts, "\n\n")
}

func extractFull(doc *html.Node) string {
	root := findContentRoot(doc)
	var sb strings.Builder
	nodeToMarkdown(&sb, root, 0)
	return strings.TrimSpace(collapseBlankLines(sb.String()))
}

// findContentRoot prefers <main> or <article>, falls back to <body>.
func findContentRoot(doc *html.Node) *html.Node {
	var main, article, body *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "main":
				if main == nil {
					main = n
				}
			case "article":
				if article == nil {
					article = n
				}
			case "body":
				body = n
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if main != nil {
		return main
	}
	if article != nil {
		return article
	}
	if body != nil {
		return body
	}
	return doc
}

var skipTags = map[string]bool{
	"script": true, "style": true, "nav": true, "footer": true,
	"aside": true, "form": true, "button": true, "iframe": true,
	"noscript": true, "svg": true, "figure": true,
}

var blockTags = map[string]bool{
	"p": true, "div": true, "section": true, "article": true,
	"header": true, "main": true, "li": true, "blockquote": true,
	"dt": true, "dd": true,
}

func nodeToMarkdown(sb *strings.Builder, n *html.Node, depth int) {
	if n.Type == html.TextNode {
		text := strings.TrimRight(n.Data, " \t")
		text = strings.ReplaceAll(text, "\n", " ")
		if strings.TrimSpace(text) != "" {
			sb.WriteString(text)
		}
		return
	}
	if n.Type != html.ElementNode {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			nodeToMarkdown(sb, c, depth)
		}
		return
	}

	tag := n.Data
	if skipTags[tag] {
		return
	}

	switch tag {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		level := int(tag[1]-'0')
		sb.WriteString("\n\n")
		sb.WriteString(strings.Repeat("#", level))
		sb.WriteString(" ")
		childrenToMarkdown(sb, n, depth)
		sb.WriteString("\n\n")

	case "p":
		sb.WriteString("\n\n")
		childrenToMarkdown(sb, n, depth)
		sb.WriteString("\n\n")

	case "br":
		sb.WriteString("\n")

	case "hr":
		sb.WriteString("\n\n---\n\n")

	case "strong", "b":
		sb.WriteString("**")
		childrenToMarkdown(sb, n, depth)
		sb.WriteString("**")

	case "em", "i":
		sb.WriteString("*")
		childrenToMarkdown(sb, n, depth)
		sb.WriteString("*")

	case "code":
		if n.Parent != nil && n.Parent.Data == "pre" {
			childrenToMarkdown(sb, n, depth)
		} else {
			sb.WriteString("`")
			childrenToMarkdown(sb, n, depth)
			sb.WriteString("`")
		}

	case "pre":
		sb.WriteString("\n\n```\n")
		childrenToMarkdown(sb, n, depth)
		sb.WriteString("\n```\n\n")

	case "blockquote":
		var inner strings.Builder
		childrenToMarkdown(&inner, n, depth)
		lines := strings.Split(strings.TrimSpace(inner.String()), "\n")
		sb.WriteString("\n\n")
		for _, line := range lines {
			sb.WriteString("> ")
			sb.WriteString(line)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")

	case "a":
		href := attr(n, "href")
		var inner strings.Builder
		childrenToMarkdown(&inner, n, depth)
		text := strings.TrimSpace(inner.String())
		if href != "" && text != "" && text != href {
			sb.WriteString("[")
			sb.WriteString(text)
			sb.WriteString("](")
			sb.WriteString(href)
			sb.WriteString(")")
		} else if text != "" {
			sb.WriteString(text)
		}

	case "img":
		alt := attr(n, "alt")
		src := attr(n, "src")
		if alt != "" && src != "" {
			sb.WriteString("![")
			sb.WriteString(alt)
			sb.WriteString("](")
			sb.WriteString(src)
			sb.WriteString(")")
		}

	case "ul":
		sb.WriteString("\n\n")
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "li" {
				sb.WriteString("- ")
				var inner strings.Builder
				childrenToMarkdown(&inner, c, depth+1)
				sb.WriteString(strings.TrimSpace(inner.String()))
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")

	case "ol":
		sb.WriteString("\n\n")
		i := 1
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "li" {
				sb.WriteString(strings.Repeat(" ", depth*2))
				sb.WriteString(strings.Replace("0. ", "0", string(rune('0'+i)), 1))
				var inner strings.Builder
				childrenToMarkdown(&inner, c, depth+1)
				sb.WriteString(strings.TrimSpace(inner.String()))
				sb.WriteString("\n")
				i++
			}
		}
		sb.WriteString("\n")

	default:
		if blockTags[tag] {
			sb.WriteString("\n")
			childrenToMarkdown(sb, n, depth)
			sb.WriteString("\n")
		} else {
			childrenToMarkdown(sb, n, depth)
		}
	}
}

func childrenToMarkdown(sb *strings.Builder, n *html.Node, depth int) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		nodeToMarkdown(sb, c, depth)
	}
}

func collapseBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	blanks := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blanks++
			if blanks <= 1 {
				out = append(out, "")
			}
		} else {
			blanks = 0
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
