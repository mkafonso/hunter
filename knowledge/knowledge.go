package knowledge

import "github.com/mkafonso/hunter/types"

func Enrich(findingMessage string) types.EnrichedInfo {
	if result := enrichPerformance(findingMessage); result != nil {
		return *result
	}
	if result := enrichSecurity(findingMessage); result != nil {
		return *result
	}
	if result := enrichStructure(findingMessage); result != nil {
		return *result
	}
	if result := enrichVulnerabilities(findingMessage); result != nil {
		return *result
	}

	return types.EnrichedInfo{}
}
