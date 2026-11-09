#include "feature_types.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>

using namespace scratcher;
static void check(bool passed, const char* message) {
 if (!passed) throw std::runtime_error(message);
}
int main() {
 try {
  const auto dir = executableDir() / "type-fixtures";
  std::filesystem::create_directories(dir);
  const auto file = dir / "typed.bin";
  // Raw x64 System V: mov eax, edi; add eax, esi; ret.
  std::vector<uint8_t> bytes(64, 0x90);
  const uint8_t add[] = {0x89, 0xf8, 0x01, 0xf0, 0xc3};
  std::copy(std::begin(add), std::end(add), bytes.begin());
  { std::ofstream out(file, std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
  Engine session;
  session.open(file);
  session.decompile(0x1000);
  auto result = setFunctionSignature(session, 0x1000, "int add_values(int left, int right);");
  check(result["applied"] == true, "signature applies");
  auto code = session.decompile(0x1000)["code"].get<std::string>();
  check(code.find("add_values") != std::string::npos, "function name reaches output");
  check(code.find("left") != std::string::npos && code.find("right") != std::string::npos,
   "parameter names reach output");
  auto types = describeFunctionTypes(session, 0x1000);
  check(types["parameters"].size() == 2 && types["return_type"] == "int", "typed prototype retained");
  setVariableType(session, 0x1000, "left", "unsigned int first;");
  code = session.decompile(0x1000)["code"].get<std::string>();
  check(code.find("first") != std::string::npos, "parameter retype and rename reaches output");
  bool rejected = false;
  try { setFunctionSignature(session, 0x1000, "not a valid declaration"); }
  catch (const std::exception&) { rejected = true; }
  check(rejected, "bad declaration rejected");
  check(session.decompile(0x1000)["code"].get<std::string>().find("first") != std::string::npos,
   "bad declaration preserves signature");
  rejected = false;
  try { setVariableType(session, 0x1000, "first", "char small;"); }
  catch (const std::exception&) { rejected = true; }
  check(rejected, "size-changing local edit rejected");
  // Replace with pointer return and input; typed pointers must change generated C.
  setFunctionSignature(session, 0x1000, "char *pointer_value(char *buffer);");
  code = session.decompile(0x1000)["code"].get<std::string>();
  check(code.find("char *") != std::string::npos && code.find("buffer") != std::string::npos,
   "pointer declaration reaches output");
  check(describeFunctionTypes(session, 0x1000)["parameters"].size() == 1, "replacement removes stale parameters");
  rejected = false;
  try { setFunctionSignature(session, 0x1000, "int same(int repeat, int repeat);"); }
  catch (const std::exception&) { rejected = true; }
  check(rejected, "duplicate parameter names rejected");
  std::cout << "PASS: function signatures, named parameters, pointer types, variable edits, validation\n";
  return 0;
 } catch (const std::exception& e) {
  std::cerr << "FAIL: " << e.what() << '\n'; return 1;
 }
}
