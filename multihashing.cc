#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
    #include "lyra2re.h"
    #include "Lyra2REV2.h"
    #include "lyra2v2.h"
    #include "lyra2z.h"
    #include "xevan.h"
    #include "phi1612.h"
}

//    #include "equi.h"

#include "boolberry.h"

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
    Isolate* isolate = Isolate::GetCurrent();
    return isolate->ThrowException(String::NewFromUtf8(isolate, msg));
}

void Scrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 3) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   unsigned int nValue = args[1]->Uint32Value();
   unsigned int rValue = args[2]->Uint32Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void Quark(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32]; 

   uint32_t input_len = Buffer::Length(target);

   quark_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void x11(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   x11_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void x5(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   x15_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void neoscrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 2) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[34];

//   uint32_t input_len = Buffer::Length(target);

   neoscrypt(input, output, 0);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void scryptn(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 2) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   unsigned int nFactor = args[1]->Uint32Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void scryptjane(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 5) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   int timestamp = args[1]->Uint32Value();

   int nChainStartTime = args[2]->Uint32Value();

   int nMin = args[3]->Uint32Value();

   int nMax = args[4]->Uint32Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);
 
   scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void yescrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void keccak(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   keccak_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void bcrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   bcrypt_hash(input, output);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void skein(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   skein_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
} 

void groestl(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
  
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
  
   Local<Object> target = args[0]->ToObject();
  
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
  
   char * input = Buffer::Data(target);
   char output[32];
  
   uint32_t input_len = Buffer::Length(target);

   groestl_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void groestlmyriad(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
  
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
  
   Local<Object> target = args[0]->ToObject();
  
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
  
   char * input = Buffer::Data(target);
   char output[32];
  
   uint32_t input_len = Buffer::Length(target);

   groestlmyriad_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void blake(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
  
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
  
   Local<Object> target = args[0]->ToObject();
  
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
  
   char * input = Buffer::Data(target);
   char output[32];
  
   uint32_t input_len = Buffer::Length(target);
 
   blake_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void dcrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
  
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
  
   Local<Object> target = args[0]->ToObject();
  
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
  
   char * input = Buffer::Data(target);
   char output[32];
  
   uint32_t input_len = Buffer::Length(target);
 
   dcrypt_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void fugue(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
  
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
  
   Local<Object> target = args[0]->ToObject();
  
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
  
   char * input = Buffer::Data(target);
   char output[32];
  
   uint32_t input_len = Buffer::Length(target);

   fugue_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void qubit(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
 
   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
 
   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   qubit_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void s3(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   s3_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void hefty1(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   hefty1_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void shavite3(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
 
   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
 
   Local<Object> target = args[0]->ToObject();
 
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
 
   char * input = Buffer::Data(target);
   char output[32];
 
   uint32_t input_len = Buffer::Length(target);
 
   shavite3_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void cryptonight(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();
 
   bool fast = false;

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
 
   if (args.Length() >= 2) {
        if(!args[1]->IsBoolean()) {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument 2 should be a boolean")));
	    return;
	}
        fast = args[1]->ToBoolean()->BooleanValue();
   }

   Local<Object> target = args[0]->ToObject();
 
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
 
   char * input = Buffer::Data(target);
   char output[32];
 
   uint32_t input_len = Buffer::Length(target);
 
   if(fast)
      cryptonight_fast_hash(input, output, input_len);
   else
      cryptonight_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void x13(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   x13_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void x14(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   x14_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void boolberry(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 2) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();
   Local<Object> target_spad = args[1]->ToObject();
   uint32_t height = 1;

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   if(!Buffer::HasInstance(target_spad)) {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument 2 should be a buffer object.")));
	return;
   }

   if(args.Length() >= 3)
       if(args[2]->IsUint32())
            height = args[2]->Uint32Value();
       else {
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument 3 should be an unsigned integer.")));
	    return;
       }

   char * input = Buffer::Data(target);
   char * scratchpad = Buffer::Data(target_spad);
   char output[32];

   uint32_t input_len = Buffer::Length(target);
   uint64_t spad_len = Buffer::Length(target_spad);

   boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void nist5(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   nist5_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void sha1(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }
 
   Local<Object> target = args[0]->ToObject();
 
   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }
 
   char * input = Buffer::Data(target);
   char output[32];
 
   uint32_t input_len = Buffer::Length(target);
 
   sha1_hash(input, output, input_len);
 
   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void x15(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   x15_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void fresh(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   fresh_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void jh(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   jh_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void c11(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

//   uint32_t input_len = Buffer::Length(target);

   c11_hash(input, output);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}
/*
void equihash(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 2) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> header = args[0]->ToObject();
   Local<Object> solution = args[1]->ToObject();

   if(!Buffer::HasInstance(header) || !Buffer::HasInstance(solution)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char *hdr = Buffer::Data(header);
   char *soln = Buffer::Data(solution);

   bool result = verifyEH(hdr, soln);

   args.GetReturnValue().Set(result);
}
*/
void xevan(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   xevan_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void lyra2re(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   lyra2re_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void lyra2v2(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   lyra2v2_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void lyra2z(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   lyra2z_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void phi1612(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   phi1612_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void lyra2rev2(const v8::FunctionCallbackInfo<v8::Value>& args) {
   v8::Isolate* isolate = args.GetIsolate();

   if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
   }

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
   }

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   lyra2rev2_hash(input, output, input_len);

   v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
   args.GetReturnValue().Set(returnValue);
}

void init(v8::Local<v8::Object> target) {
    NODE_SET_METHOD(target, "scrypt", Scrypt);
    NODE_SET_METHOD(target, "quark", Quark);
    NODE_SET_METHOD(target, "x11", x11);
    NODE_SET_METHOD(target, "x5", x5);
    NODE_SET_METHOD(target, "neoscrypt", neoscrypt);
    NODE_SET_METHOD(target, "scryptn", scryptn);
    NODE_SET_METHOD(target, "scryptjane", scryptjane);
    NODE_SET_METHOD(target, "yescrypt", yescrypt);
    NODE_SET_METHOD(target, "keccak", keccak);
    NODE_SET_METHOD(target, "bcrypt", bcrypt);
    NODE_SET_METHOD(target, "skein", skein);
    NODE_SET_METHOD(target, "groestl", groestl);
    NODE_SET_METHOD(target, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(target, "blake", blake);
    NODE_SET_METHOD(target, "dcrypt", dcrypt);
    NODE_SET_METHOD(target, "fugue", fugue);
    NODE_SET_METHOD(target, "qubit", qubit);
    NODE_SET_METHOD(target, "s3", s3);
    NODE_SET_METHOD(target, "hefty1", hefty1);
    NODE_SET_METHOD(target, "havite3", shavite3);
    NODE_SET_METHOD(target, "cryptonight", cryptonight);
    NODE_SET_METHOD(target, "x13", x13);
    NODE_SET_METHOD(target, "x14", x14);
    NODE_SET_METHOD(target, "boolberry", boolberry);
    NODE_SET_METHOD(target, "nist5", nist5);
    NODE_SET_METHOD(target, "sha1", sha1);
    NODE_SET_METHOD(target, "sha1", sha1);
    NODE_SET_METHOD(target, "x15", x15);
    NODE_SET_METHOD(target, "fresh", fresh);
//    NODE_SET_METHOD(target, "equihash", equihash);
    NODE_SET_METHOD(target, "jh", jh);
    NODE_SET_METHOD(target, "c11", c11);
    NODE_SET_METHOD(target, "lyra2re", lyra2re);
    NODE_SET_METHOD(target, "lyra2rev2", lyra2rev2);
    NODE_SET_METHOD(target, "lyra2v2", lyra2v2);
    NODE_SET_METHOD(target, "lyra2z", lyra2z);
    NODE_SET_METHOD(target, "xevan", xevan);
    NODE_SET_METHOD(target, "phi1612", phi1612);
}

NODE_MODULE(multihashing, init)
