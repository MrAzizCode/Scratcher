#include "feature_annotations.hpp"
#include <cassert>
#include <iostream>

int main() {
 using namespace scratcher;
 AnnotationStore annotations;
 annotations.setComment(0x2000,"Line one\n\xd8\xaa\xd8\xb9\xd9\x84\xd9\x8a\xd9\x82");
 annotations.setBookmark(0x1000,"");
 annotations.setLabel(0x2000,"process_input");
 assert(annotations.list()["annotations"][0]["address"]=="0x1000");
 assert(annotations.list(0x2000)["count"]==1);
 assert(annotations.list(0x3000)["count"]==0);
 AnnotationStore restored;
 restored.importState(Json::parse(annotations.exportState().dump()));
 assert(restored.exportState()==annotations.exportState());
 const auto before=restored.exportState();
 auto expectFailure=[&](auto action) { bool failed=false; try { action(); } catch (const std::exception&) { failed=true; } assert(failed); assert(restored.exportState()==before); };
 expectFailure([&]{restored.setComment(1,std::string(AnnotationStore::maxCommentBytes+1,'x'));});
 expectFailure([&]{restored.setComment(1,std::string("\xc0\xaf",2));});
 expectFailure([&]{restored.setComment(1,std::string("a\0b",3));});
 expectFailure([&]{restored.setLabel(1,"bad\nlabel");});
 expectFailure([&]{auto invalid=before; invalid["annotations"].push_back(invalid["annotations"][0]); restored.importState(invalid);});
 expectFailure([&]{auto invalid=before; invalid["annotations"][0]["comment"]=42; restored.importState(invalid);});
 assert(restored.removeBookmark(0x1000)["removed"]==true);
 assert(restored.removeBookmark(0x1000)["removed"]==false);
 restored.setComment(0x2000,"");
 assert(restored.list()["count"]==1);
 restored.setLabel(0x2000,"");
 assert(restored.list()["count"]==0);
 restored.clear();
 std::cout << "Annotation tests passed\n";
}
