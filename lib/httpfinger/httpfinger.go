package httpfinger

import (
	"encoding/json"
)

var CountFaviconHash = 0
var CountKeywordFinger = 0

func Init() {
	_ = json.Unmarshal(faviconHashByte, &FaviconHash)
	_ = json.Unmarshal(keywordFingerSourceByte, &KeywordFinger)
	var keywordFingerFofa keywordFinger
	_ = json.Unmarshal(keywordFingerFofaByte, &keywordFingerFofa)
	KeywordFinger = append(KeywordFinger, keywordFingerFofa...)

	CountFaviconHash = len(FaviconHash)
	CountKeywordFinger = len(KeywordFinger)
}
