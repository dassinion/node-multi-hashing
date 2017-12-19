#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "scryptn.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
    Isolate* isolate = Isolate::GetCurrent();
    return isolate->ThrowException(String::NewFromUtf8(isolate, msg));
}

void Scrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
   v8::HandleScope scope(isolate);

   if (args.Length() < 3) {
       except("You must provide buffer to hash, N value, and R value");
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       except("Argument should be a buffer object.");
       return;
   }

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
}

void init(v8::Local<v8::Object> target) {
    NODE_SET_METHOD(target, "scrypt", Scrypt);
}

NODE_MODULE(multihashing, init)
