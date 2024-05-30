CXX=g++
CFLAGS=-g3 -O0 -pedantic -Wall -fsanitize=address
CXXFLAGS=-std=c++11 $(CFLAGS)

DEPS = c_keywords.h list.h utils.h hash_map.h call_graph.h check_expression.h sanitize_expression.h struct_parse.h token_get.h file_search.h assignment_parse.h func_call_parse.h expand_call_graph.h var_search.h 
OBJECTS = list.o hash_map.o utils.o check_expression.o call_graph.o sanitize_expression.o struct_parse.o token_get.o file_search.o assignment_parse.o func_call_parse.o expand_call_graph.o var_search.o

all: hash_map.o knob_search search_call_graph

hash_map.o: hash_map.cpp
	$(CXX) $(CXXFLAGS) -c -o hash_map.o hash_map.cpp

%.o: %.c $(DEPS)
	$(CXX) $(CFLAGS) -c -o $@ $<

knob_search: $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^

search_call_graph.o: search_call_graph.c
	$(CXX) $(CXXFLAGS) -c -o search_call_graph.o search_call_graph.c

search_call_graph: list.o hash_map.o call_graph.o utils.o search_call_graph.o
	$(CXX) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o *~ knob_search
