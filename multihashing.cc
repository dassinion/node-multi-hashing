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
//   v8::HandleScope scope(isolate);

   if (args.Length() < 3) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
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
   MaybeLocal<Object> buffer = Nan::NewBuffer(output, 32);
   args.GetReturnValue().Set(buffer.ToLocalChecked());
}

void init(v8::Local<v8::Object> target) {
    NODE_SET_METHOD(target, "scrypt", Scrypt);
}

NODE_MODULE(multihashing, init)
