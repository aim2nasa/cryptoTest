CXX = g++

TARGET = runTests
SRCS = main.cpp util.cpp aesBase.cpp aesECB.cpp aesCBC.cpp
OBJS = ${SRCS:.cpp=.o}

GTEST_LIBRARIES = -lgtest -lpthread
CRYPTOPP_LIBRARIES = -lcryptopp
LIBS = $(GTEST_LIBRARIES) $(CRYPTOPP_LIBRARIES)

all : $(TARGET)
	@echo $@:$(TARGET)...

$(TARGET) : $(OBJS)
	@echo $@:$^...
	$(CXX) -o $@ $^ $(LIBS)

%.o : %.cpp
	@echo $@:$<...
	$(CXX) -c $< 

clean:
	@echo $@...
	rm -rf *.o $(TARGET)
