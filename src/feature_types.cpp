#include "feature_types.hpp"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "type.hh"
#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <regex>

namespace scratcher {
namespace {
bool identifier(const std::string& text) {
 return !text.empty() && text.size() <= 128 &&
  (std::isalpha(static_cast<unsigned char>(text.front())) || text.front() == '_') &&
  std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; });
}
std::string declarationText(const std::string& text) {
 if (text.empty() || text.size() > 4096)
  throw std::runtime_error("Enter a C declaration up to 4096 characters");
 if (std::any_of(text.begin(), text.end(), [](unsigned char c) {
  return c == 0 || (c < 32 && c != '\n' && c != '\r' && c != '\t') ||
         c == '{' || c == '}' || c == '#' || c == '"' || c == '\'';
 })) throw std::runtime_error("Enter a single C declaration without a body");
 auto result = text;
 while (!result.empty() && std::isspace(static_cast<unsigned char>(result.back()))) result.pop_back();
 if (result.empty()) throw std::runtime_error("Enter a C declaration");
 if (result.back() != ';') result += ';';
 if (result.find(';') != result.size() - 1)
  throw std::runtime_error("Enter one declaration at a time");
 static const std::vector<std::pair<std::string,std::string>> aliases={
  {"unsigned\\s+long\\s+long(?:\\s+int)?","uint64_t"},{"signed\\s+long\\s+long(?:\\s+int)?","__int64"},{"long\\s+long(?:\\s+int)?","__int64"},
  {"unsigned\\s+long(?:\\s+int)?","ulong"},{"unsigned\\s+short(?:\\s+int)?","ushort"},{"unsigned\\s+char","uchar"},{"unsigned(?:\\s+int)?","uint"},
  {"signed\\s+char","schar"},{"signed\\s+short(?:\\s+int)?","short"},{"signed\\s+long(?:\\s+int)?","long"},{"signed(?:\\s+int)?","int"},{"short\\s+int","short"},{"long\\s+int","long"}};
 for(auto&[pattern,replacement]:aliases)result=std::regex_replace(result,std::regex("\\b"+pattern+"\\b"),replacement);
 return result;
}
ghidra::Funcdata* functionAt(Engine& engine, ghidra::Architecture* arch, Address va) {
 if (!engine.binary() || !engine.binary()->analysisCode(va))
  throw std::runtime_error("Choose an address in executable memory");
 auto addr = ghidra::Address(arch->getDefaultCodeSpace(), va);
 auto* scope = arch->symboltab->getGlobalScope();
 auto* fn = scope->queryFunction(addr);
 if (!fn) fn = scope->addFunction(addr, "sub_" + hex(va).substr(2))->getFunction();
 return fn;
}
std::string typeText(ghidra::Datatype* type, unsigned depth = 0) {
 if (!type || depth > 16) return "void";
 if (!type->getName().empty()) return type->getName();
 if (type->getMetatype() == ghidra::TYPE_PTR)
  return typeText(static_cast<ghidra::TypePointer*>(type)->getPtrTo(), depth + 1) + " *";
 std::ostringstream out; type->printRaw(out); return out.str();
}
Json parameter(ghidra::ProtoParameter* p) {
 Json result = {{"name", p->getName()}, {"type", typeText(p->getType())},
  {"size", p->getSize()}, {"type_locked", p->isTypeLocked()}};
 auto location = p->getAddress();
 if (!location.isInvalid()) {
  result["storage"] = location.getSpace()->getName();
  result["offset"] = hex(location.getOffset());
 }
 return result;
}
std::string signatureText(ghidra::Funcdata* fn) {
 auto& proto = fn->getFuncProto();
 std::ostringstream out;
 out << typeText(proto.getOutputType()) << ' ';
 if (!proto.getModelName().empty()) out << proto.getModelName() << ' ';
 out << fn->getName() << '(';
 for (int i = 0; i < proto.numParams(); ++i) {
  if (i) out << ", ";
  auto* p = proto.getParam(i);
  out << typeText(p->getType());
  if (!p->getName().empty()) out << ' ' << p->getName();
 }
 if (proto.isDotdotdot()) out << (proto.numParams() ? ", ..." : "...");
 else if (!proto.numParams()) out << "void";
 out << ");";
 return out.str();
}
void clearFunctionAnalysis(Engine& engine, ghidra::Architecture* arch, ghidra::Funcdata* target) {
 // Call sites must be rebuilt to use changed parameter/return types.
 arch->clearAnalysis(target);
 auto* scope=arch->symboltab->getGlobalScope();
 for (auto entry=scope->begin();entry!=scope->end();++entry) {
  auto* symbol=dynamic_cast<ghidra::FunctionSymbol*>((*entry)->getSymbol());
  auto* fn=symbol?symbol->getFunction():nullptr;
  if (fn && fn != target && fn->isProcStarted()) arch->clearAnalysis(fn);
 }
 engine.invalidateDecompilation();
}
Json describe(ghidra::Funcdata* fn, Address va) {
 auto& proto = fn->getFuncProto();
 Json inputs = Json::array(), locals = Json::array();
 for (int i = 0; i < proto.numParams(); ++i) {
  auto row = parameter(proto.getParam(i)); row["index"] = i; inputs.push_back(std::move(row));
 }
 std::set<ghidra::Symbol*> visited;
 auto addLocal = [&](ghidra::Symbol* sym) {
  if (!sym || sym->getCategory() != ghidra::Symbol::no_category ||
      !visited.insert(sym).second || locals.size() >= 2048) return;
  locals.push_back({{"name", sym->getName()}, {"type", typeText(sym->getType())},
   {"size", sym->getType()->getSize()}, {"type_locked", sym->isTypeLocked()}});
 };
 auto* scope = fn->getScopeLocal();
 for (auto it = scope->begin(); it != scope->end(); ++it) addLocal((*it)->getSymbol());
 for (auto it = scope->beginDynamic(); it != scope->endDynamic(); ++it) addLocal(it->getSymbol());
 return {{"address", hex(va)}, {"name", fn->getName()}, {"signature", signatureText(fn)},
  {"calling_convention", proto.getModelName()}, {"return_type", typeText(proto.getOutputType())},
  {"parameters", inputs}, {"locals", locals}, {"variadic", proto.isDotdotdot()},
  {"input_locked", proto.isInputLocked()}, {"output_locked", proto.isOutputLocked()}};
}
}
Json setFunctionSignature(Engine& engine, Address va, const std::string& declaration) {
  auto text = declarationText(declaration);
 try {
  auto* arch = engine.nativeArchitecture();
  auto* fn = functionAt(engine, arch, va);
  ghidra::PrototypePieces pieces{};
  std::istringstream input(text);
  ghidra::parse_protopieces(pieces, input, arch);
  if (!identifier(pieces.name)) throw std::runtime_error("Use a C identifier for the function name");
  if (pieces.intypes.size() > 64) throw std::runtime_error("A signature supports at most 64 parameters");
  std::set<std::string> names;
  for (size_t i = 0; i < pieces.innames.size(); ++i) {
   auto& name = pieces.innames[i];
   if (name.empty()) name = "arg" + std::to_string(i + 1);
   if (!identifier(name) || !names.insert(name).second)
    throw std::runtime_error("Use distinct C identifiers for parameter names");
  }
  // Resolve storage before changing the existing function. This also catches
  // unsupported combinations of return type and calling convention.
  std::vector<ghidra::ParameterPieces> assigned;
  pieces.model->assignParameterStorage(pieces, assigned, false);
  clearFunctionAnalysis(engine, arch, fn);
  fn->getFuncProto().setPieces(pieces);
  for (int i = 0; i < fn->getFuncProto().numParams(); ++i)
   fn->getFuncProto().getParam(i)->setNameLock(true);
  auto indexed = std::find_if(engine.binary()->functions.begin(), engine.binary()->functions.end(),
   [va](const Function& f) { return f.va == va; });
  if (indexed != engine.binary()->functions.end()) engine.rename(va, pieces.name);
  else fn->getSymbol()->getScope()->renameSymbol(fn->getSymbol(), pieces.name);
  auto result = describe(fn, va); result["applied"] = true; result["declaration"] = declaration;
  return result;
 } catch (const ghidra::ParseError& error) {
  throw std::runtime_error("Invalid C signature: " + error.explain);
 } catch (const ghidra::LowlevelError&) {
  throw std::runtime_error("The signature cannot be applied with this calling convention or these types");
 }
}
Json describeFunctionTypes(Engine& engine, Address va) {
 try {
  engine.decompile(va);
  auto* arch = engine.nativeArchitecture();
  return describe(functionAt(engine, arch, va), va);
 } catch (const ghidra::LowlevelError&) {
  throw std::runtime_error("Unable to inspect function types at this address");
 }
}
Json setVariableType(Engine& engine, Address va, const std::string& name, const std::string& declaration) {
 if (!identifier(name)) throw std::runtime_error("Choose a variable by its C identifier");
 auto text = declarationText(declaration);
 text.pop_back();
 try {
  engine.decompile(va);
  auto* arch = engine.nativeArchitecture();
  auto* fn = functionAt(engine, arch, va);
  std::string newName;
  std::istringstream input(text);
  auto* type = ghidra::parse_type(input, newName, arch);
  if (!newName.empty() && !identifier(newName)) throw std::runtime_error("Use a C identifier for the variable name");
  if (type->getSize() <= 0 || type->getSize() > 4096 || type->getMetatype() == ghidra::TYPE_CODE)
   throw std::runtime_error("Choose a value type or pointer type up to 4096 bytes");
  std::vector<ghidra::Symbol*> symbols;
  fn->getScopeLocal()->findByName(name, symbols);
  if (symbols.empty()) throw std::runtime_error("Variable not found in this function");
  if (symbols.size() != 1) throw std::runtime_error("This variable name is ambiguous");
  auto* sym = symbols.front();
  if (sym->getType()->getSize() != type->getSize())
   throw std::runtime_error("Choose a type with the same byte size as the variable");
  auto* scope = sym->getScope();
  if (sym->getCategory() == ghidra::Symbol::function_parameter) fn->getFuncProto().setInputLock(true);
  scope->retypeSymbol(sym, type);
  scope->setAttribute(sym, ghidra::Varnode::typelock | ghidra::Varnode::namelock);
  if (!newName.empty() && newName != name) scope->renameSymbol(sym, newName);
  arch->clearAnalysis(fn);
  engine.invalidateDecompilation();
  return {{"address", hex(va)}, {"name", newName.empty() ? name : newName},
   {"type", typeText(type)}, {"applied", true}, {"declaration", declaration}};
 } catch (const ghidra::ParseError&) {
  throw std::runtime_error("Invalid C variable declaration. Try: int count; or char *buffer;");
 } catch (const ghidra::LowlevelError&) {
  throw std::runtime_error("The variable type could not be applied");
 }
}
}
