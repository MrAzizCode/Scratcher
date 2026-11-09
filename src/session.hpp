#pragma once
#include "feature_annotations.hpp"
#include "feature_patches.hpp"
namespace scratcher {
class SessionFeatures {
public:
 AnnotationStore notes;
 PatchStore patches;
 Json references;
 size_t referenceBudget=0;
 Json analysisReport;
 size_t analysisBudget=0;
 std::map<Address,std::string> signatures;
 Json variableEdits=Json::array();
 Json decoded=Json::object(),graphs=Json::object();
 size_t decodedBytes=0,graphBytes=0;
};
}
