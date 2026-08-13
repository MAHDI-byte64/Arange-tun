package mimic

import "embed"

// daAssets holds the real DirectAdmin "Evolution" login assets (light + dark logos
// and backgrounds, favicon), captured verbatim from a live panel and served at
// their original /evo/assets/ paths so the decoy's asset requests match a genuine
// panel. All are embedded in the binary — nothing to ship separately.
//
//go:embed daassets/logo.fe968txS.svg daassets/logo2.AfEZecTW.svg daassets/background.Cx34YJbp.svg daassets/background-dark.BawLIQ0N.svg daassets/favicon.CDLA4ANV.png
var daAssets embed.FS
