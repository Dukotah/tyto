package takeover

import "strings"

// Fingerprint is one third-party service known to be affected by dangling-DNS
// subdomain takeovers. It pairs the CNAME-target suffixes that indicate the
// service with the exact response signature shown when the resource is
// UNCLAIMED.
//
// Both halves are load-bearing for precision:
//   - CNAMESuffixes gate (a): the host must point here.
//   - Bodies / StatusBodies gate (b): the page must show one of these exact
//     unclaimed strings. These are the verbatim, provider-emitted texts for an
//     unregistered resource — NOT generic 404 text — so a claimed page (which
//     never contains them) is never matched.
type Fingerprint struct {
	// Service is the human-readable provider name.
	Service string
	// CNAMESuffixes are DNS-target suffixes that indicate this provider. A host's
	// resolved CNAME matches if it equals a suffix or ends in "." + suffix.
	CNAMESuffixes []string
	// Bodies are exact substrings the provider serves for an UNCLAIMED resource,
	// matched literally (case-sensitive) against the fetched body. Any one match
	// satisfies gate (b).
	Bodies []string
	// StatusBodies are status-qualified body fingerprints: the body substring is
	// only accepted as an unclaimed signal when the HTTP status also matches.
	// Used where the unclaimed text is generic enough that the status code adds
	// necessary precision (e.g. a 404 plus a specific not-found phrase).
	StatusBodies []StatusBody
	// NXDomainUnclaimed marks providers where the CNAME TARGET itself fails to
	// resolve (NXDOMAIN) when the resource is unclaimed. For these, a definitive
	// DNS signal can confirm the takeover without an HTTP body. Only set this for
	// services where NXDOMAIN-on-target is a RELIABLE unclaimed signal (e.g.
	// dangling Amazon/Azure/Google cloud resource records), never for shared
	// front-ends that always resolve.
	NXDomainUnclaimed bool
}

// StatusBody is a body fingerprint qualified by an exact HTTP status code.
type StatusBody struct {
	Status int
	Body   string
}

// matchCNAME reports whether the (already-normalized) CNAME target falls under
// any of this fingerprint's suffixes.
func (f Fingerprint) matchCNAME(cname string) bool {
	if cname == "" {
		return false
	}
	for _, suf := range f.CNAMESuffixes {
		suf = strings.ToLower(strings.TrimSuffix(suf, "."))
		if cname == suf || strings.HasSuffix(cname, "."+suf) {
			return true
		}
	}
	return false
}

// matchBody reports whether the fetched body/status shows this provider's
// unclaimed signal, returning the matched fingerprint string. Plain Bodies match
// on substring regardless of status; StatusBodies additionally require the exact
// status code, adding precision where the phrase alone is weaker.
func (f Fingerprint) matchBody(body string, status int) (string, bool) {
	for _, b := range f.Bodies {
		if b != "" && strings.Contains(body, b) {
			return b, true
		}
	}
	for _, sb := range f.StatusBodies {
		if sb.Body != "" && status == sb.Status && strings.Contains(body, sb.Body) {
			return sb.Body, true
		}
	}
	return "", false
}

// Fingerprints returns a copy of the built-in high-precision fingerprint
// database. Entries are sourced from the public takeover community corpora
// (can-i-take-over-xyz, the subjack/nuclei takeover signatures) and pruned to
// the high-confidence, currently-vulnerable services with EXACT unclaimed
// strings. Each Bodies entry is the verbatim text the provider serves for an
// unregistered resource — chosen to be absent from any live, claimed page.
func Fingerprints() []Fingerprint {
	// Return a fresh slice so callers cannot mutate the shared database.
	out := make([]Fingerprint, len(builtin))
	copy(out, builtin)
	return out
}

// builtin is the seed database. ~30 entries across the services most commonly
// reported as takeover-able with a stable, exact unclaimed fingerprint.
var builtin = []Fingerprint{
	{
		Service:       "GitHub Pages",
		CNAMESuffixes: []string{"github.io", "github.map.fastly.net"},
		Bodies: []string{
			"There isn't a GitHub Pages site here.",
			"For root URLs (like http://example.com/) you must provide an index.html file",
		},
	},
	{
		Service:       "AWS S3",
		CNAMESuffixes: []string{"s3.amazonaws.com", "s3-website.amazonaws.com", "s3-website-us-east-1.amazonaws.com", "amazonaws.com"},
		Bodies: []string{
			"NoSuchBucket",
			"The specified bucket does not exist",
		},
	},
	{
		Service:       "Heroku",
		CNAMESuffixes: []string{"herokuapp.com", "herokudns.com", "herokussl.com"},
		Bodies: []string{
			"No such app",
			"herokucdn.com/error-pages/no-such-app.html",
		},
	},
	{
		Service:       "Fastly",
		CNAMESuffixes: []string{"fastly.net"},
		Bodies: []string{
			"Fastly error: unknown domain",
			"Please check that this domain has been added to a service",
		},
	},
	{
		Service:       "Shopify",
		CNAMESuffixes: []string{"myshopify.com"},
		// "Only one step left!" also shows on legitimately-claimed stores mid-
		// onboarding — dropped. Only the verbatim unavailable string remains.
		Bodies: []string{
			"Sorry, this shop is currently unavailable",
		},
	},
	{
		Service:       "Surge.sh",
		CNAMESuffixes: []string{"surge.sh"},
		Bodies:        []string{"project not found"},
	},
	{
		Service:       "Tumblr",
		CNAMESuffixes: []string{"domains.tumblr.com"},
		Bodies: []string{
			"Whatever you were looking for doesn't currently exist at this address.",
			"There's nothing here.",
		},
	},
	// Zendesk removed: its "Help Center Closed" / "no longer exists" strings also
	// appear on legitimately-claimed-but-closed help centers (not takeover-able),
	// and it has no reliable unclaimed-only fingerprint. Precision over coverage.
	{
		Service:       "Cargo Collective",
		CNAMESuffixes: []string{"cargocollective.com"},
		// Generic "404 Not Found" dropped — only the Cargo-specific title remains.
		Bodies: []string{"<title>404 &mdash; File not found</title>"},
	},
	{
		Service:       "Webflow",
		CNAMESuffixes: []string{"proxy-ssl.webflow.com", "proxy.webflow.com", "webflow.io"},
		Bodies: []string{
			"The page you are looking for doesn't exist or has been moved.",
			"<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>",
		},
	},
	{
		Service:       "Unbounce",
		CNAMESuffixes: []string{"unbouncepages.com"},
		Bodies: []string{
			"The requested URL was not found on this server.",
			"Sorry, this page does not exist",
		},
	},
	{
		Service:       "Pantheon",
		CNAMESuffixes: []string{"pantheonsite.io", "pantheon.io"},
		Bodies: []string{
			"The gods are wise, but do not know of the site which you seek.",
			"404 error unknown site!",
		},
	},
	{
		Service:       "Ghost",
		CNAMESuffixes: []string{"ghost.io"},
		Bodies: []string{
			"The thing you were looking for is no longer here, or never was",
			"Domain error",
		},
	},
	{
		Service:       "Help Scout",
		CNAMESuffixes: []string{"helpscoutdocs.com"},
		Bodies:        []string{"No settings were found for this company:"},
	},
	{
		Service:       "Readme.io",
		CNAMESuffixes: []string{"readme.io", "readmessl.com"},
		Bodies:        []string{"Project doesnt exist... yet!", "The creators of this project are still working on making everything perfect!"},
	},
	{
		Service:       "Bitbucket",
		CNAMESuffixes: []string{"bitbucket.io"},
		Bodies:        []string{"Repository not found", "The page you have requested does not exist"},
	},
	// Wordpress.com removed: "Do you want to register" is weak/generic on the
	// always-resolving shared wordpress.com frontend (no dangling-DNS signal).
	{
		Service:       "Tilda",
		CNAMESuffixes: []string{"tilda.ws"},
		Bodies:        []string{"Please renew your subscription", "Domain has been assigned"},
	},
	{
		Service:       "Strikingly",
		CNAMESuffixes: []string{"s.strikinglydns.com", "strikinglydns.com"},
		// Generic "page not found" dropped — only the Strikingly-specific phrase.
		Bodies: []string{"But if you're looking to build your own website,"},
	},
	{
		Service:       "Uservoice",
		CNAMESuffixes: []string{"uservoice.com"},
		Bodies:        []string{"This UserVoice subdomain is currently available!"},
	},
	{
		Service:       "Intercom",
		CNAMESuffixes: []string{"custom.intercom.help"},
		Bodies:        []string{"This page is reserved for artistic dogs.", "Uh oh. That page doesn't exist."},
	},
	{
		Service:       "Help Juice",
		CNAMESuffixes: []string{"helpjuice.com"},
		Bodies:        []string{"We could not find what you're looking for."},
	},
	{
		Service:       "Pingdom",
		CNAMESuffixes: []string{"stats.pingdom.com"},
		Bodies:        []string{"Sorry, couldn't find the status page"},
	},
	{
		Service:       "Tave",
		CNAMESuffixes: []string{"clientaccess.tave.com"},
		Bodies:        []string{"<h1>Error 404: Page Not Found</h1>"},
	},
	{
		Service:       "Wishpond",
		CNAMESuffixes: []string{"wishpond.com"},
		Bodies:        []string{"https://www.wishpond.com/404?campaign=true"},
	},
	{
		Service:       "Aftership",
		CNAMESuffixes: []string{"aftership.com"},
		Bodies:        []string{"Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."},
	},
	{
		Service:       "Aha!",
		CNAMESuffixes: []string{"ideas.aha.io"},
		Bodies:        []string{"There is no portal here ... sending you back to Aha!"},
	},
	{
		Service:       "Brightcove",
		CNAMESuffixes: []string{"bcvp0rtal.com", "brightcovegallery.com", "gallery.video"},
		Bodies:        []string{"<p class=\"bc-gallery-error-code\">Error Code: 404</p>"},
	},
	{
		Service:       "Campaign Monitor",
		CNAMESuffixes: []string{"createsend.com"},
		Bodies:        []string{"Trying to access your account?", "Double check the URL"},
	},
	{
		Service:       "Acquia",
		CNAMESuffixes: []string{"acquia-sites.com"},
		Bodies:        []string{"The site you are looking for could not be found."},
	},
	{
		Service:       "Netlify",
		CNAMESuffixes: []string{"netlify.app", "netlify.com"},
		// Netlify's unclaimed page is a plain 404 with this exact phrase. Status-
		// qualified ONLY — an unqualified body match here flags claimed 200 pages.
		StatusBodies: []StatusBody{{Status: 404, Body: "Not Found - Request ID:"}},
	},
	{
		Service: "Azure (cloudapp / trafficmanager / azurewebsites)",
		// azureedge.net (shared CDN) and azure-api.net dropped: they are shared
		// front-ends where a target NXDOMAIN is not a reliable takeover signal.
		CNAMESuffixes: []string{"cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "azurewebsites.net"},
		// A dangling Azure resource record NXDOMAINs on the target — the DNS
		// signal is definitive for these. No reliable shared body fingerprint.
		NXDomainUnclaimed: true,
	},
	{
		Service:       "AWS Elastic Beanstalk",
		CNAMESuffixes: []string{"elasticbeanstalk.com"},
		// Dangling EB environments stop resolving — NXDOMAIN on the target.
		NXDomainUnclaimed: true,
	},
}
