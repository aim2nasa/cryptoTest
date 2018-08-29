CXX = g++

TARGET = aesExample
SRCS = aesExample.cpp
OBJS = ${SRCS:.cpp=.o}

CRYPTOPP_LIBRARY = -lcryptopp

LIBS = $(CRYPTOPP_LIBRARY)

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
