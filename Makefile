CXX ?= g++
FUZZ_CXX ?= clang++
BUILD ?= build/linux
SANITIZE ?= 0

CXXFLAGS ?= -std=c++20 -O1 -g -Wall -Wextra -Wpedantic -Werror
CPPFLAGS := -Iinclude -Isrc -Itests

ifeq ($(SANITIZE),1)
SANITIZER_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
endif

LIB_SOURCES := $(shell find src -name '*.cpp' ! -path 'src/platform/windows/*' ! -name 'c_sandbox.cpp' | sort)
TEST_SOURCES := $(shell find tests -name '*.cpp' | sort)
FUZZ_TARGETS := $(patsubst fuzz/%.cpp,$(BUILD)/fuzz/%,$(wildcard fuzz/*.cpp))

LIB_OBJECTS := $(LIB_SOURCES:%.cpp=$(BUILD)/obj/%.o)
TEST_OBJECTS := $(TEST_SOURCES:%.cpp=$(BUILD)/obj/%.o)

.PHONY: all test fuzz clean

all: $(BUILD)/glaipnir_tests

test: $(BUILD)/glaipnir_tests
	./$(BUILD)/glaipnir_tests

fuzz: $(FUZZ_TARGETS)

$(BUILD)/libglaipnir.a: $(LIB_OBJECTS)
	ar rcs $@ $^

$(BUILD)/glaipnir_tests: $(TEST_OBJECTS) $(BUILD)/libglaipnir.a
	$(CXX) $(CXXFLAGS) $(SANITIZER_FLAGS) -o $@ $^

$(BUILD)/obj/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SANITIZER_FLAGS) -MMD -MP -c $< -o $@

$(BUILD)/fuzz/%: fuzz/%.cpp $(LIB_SOURCES)
	@mkdir -p $(dir $@)
	$(FUZZ_CXX) $(CPPFLAGS) -std=c++20 -O1 -g -fsanitize=fuzzer,address,undefined -o $@ $< $(LIB_SOURCES)

clean:
	rm -rf $(BUILD)

-include $(LIB_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
