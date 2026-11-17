//! Share card: counts only, as a 1200x630 SVG. No names, hosts, paths or dates.

use crate::model::*;
use crate::render::html::esc;

pub fn render(r: &Report) -> String {
    let s = &r.summary;
    let tiles = [
        (s.web_services, "AI web services"),
        (s.agents + s.cli_tools, "agents and AI CLIs"),
        (s.mcp_servers, "MCP servers"),
        (s.skills + s.plugins + s.customizations, "skills, rules and plugins"),
        (s.ide_extensions, "IDE extensions"),
        (s.api_keys, "AI API keys"),
    ];
    // Counts-only line: never the headline, which can carry a server name.
    let worst_line = match s.worst {
        Some(c) => {
            let n = r.findings.iter().filter(|f| f.capabilities.first() == Some(&c)).count();
            format!("{n} {} {}", if n == 1 { "item" } else { "items" }, c.phrase())
        }
        None => "Nothing shown to hold a risky capability".to_string(),
    };
    let mut o = String::new();
    o.push_str("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1200\" height=\"630\" viewBox=\"0 0 1200 630\" font-family=\"-apple-system,Segoe UI,Roboto,sans-serif\">");
    o.push_str("<rect width=\"1200\" height=\"630\" fill=\"#141413\"/>");
    o.push_str("<text x=\"64\" y=\"104\" font-size=\"52\" font-weight=\"700\" fill=\"#ecebe6\">My AI footprint</text>");
    o.push_str("<text x=\"64\" y=\"150\" font-size=\"24\" fill=\"#a3a29b\">One laptop, scanned locally. Nothing was uploaded.</text>");
    for (i, (n, label)) in tiles.iter().enumerate() {
        let x = 64 + (i % 3) * 360;
        let y = 200 + (i / 3) * 150;
        o.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"336\" height=\"126\" rx=\"12\" fill=\"#1c1c1a\" stroke=\"#2e2d2a\"/>\
             <text x=\"{}\" y=\"{}\" font-size=\"56\" font-weight=\"700\" fill=\"#ecebe6\">{n}</text>\
             <text x=\"{}\" y=\"{}\" font-size=\"22\" fill=\"#a3a29b\">{}</text>",
            x + 24,
            y + 66,
            x + 24,
            y + 102,
            esc(label)
        ));
    }
    let countries: std::collections::BTreeSet<&str> = s.destinations.iter().filter_map(|d| d.country.as_deref()).filter(|c| *c != "LOCAL").collect();
    let country_line = if countries.is_empty() {
        "No upstream AI provider traced".to_string()
    } else {
        format!("Data can reach AI providers based in {} {}: {}", countries.len(), if countries.len() == 1 { "country" } else { "countries" }, countries.iter().copied().collect::<Vec<_>>().join(", "))
    };
    o.push_str(&format!("<text x=\"64\" y=\"512\" font-size=\"28\" font-weight=\"600\" fill=\"#f97066\">{}</text>", esc(&worst_line)));
    o.push_str(&format!("<text x=\"64\" y=\"552\" font-size=\"24\" fill=\"#ecebe6\">{}</text>", esc(&country_line)));
    o.push_str("<text x=\"64\" y=\"598\" font-size=\"20\" fill=\"#a3a29b\">LightCast · open source · auspere.ai/lightcast</text>");
    o.push_str("</svg>\n");
    o
}
