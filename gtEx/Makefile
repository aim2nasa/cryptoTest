CXX = g++
CXXFLAGS = -std=c++11

TARGET = runTests
SRCS = tests.cpp
OBJS = ${SRCS:.cpp=.o}

GTEST_INCLUDE_DIRS=/usr/include
GTEST_LIBRARIES=/usr/lib

INCLUDES = $(GTEST_INCLUDE_DIRS)
LIBS = -L$(GTEST_LIBRARIES) -lgtest -lpthread

all : $(TARGET)
	@echo $@:$(TARGET)...

$(TARGET) : $(OBJS)
	@echo $@:$^...
	$(CXX) -o $@ $^ $(LIBS)

%.o : %.cpp
	@echo $@:$<...
	$(CXX) -c $< $(CXXFLAGS)

clean:
	@echo $@...
	rm -rf *.o $(TARGET)
