#define NODE_API_SWALLOW_UNTHROWABLE_EXCEPTIONS 1
#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <napi.h>
#include <indicators.hpp>
#include "Ap4.h"

using namespace indicators;
class ProgressListener : public AP4_Processor::ProgressListener {
  public:
    AP4_Result OnProgress(unsigned int step, unsigned int total);
};


ProgressBar bar {
  option::BarWidth{40},
  option::Start{"["},
  option::Fill{"="},
  option::Lead{"="},
  option::Remainder{" "},
  option::End{"]"},
  option::PostfixText{"Decrypting"},
  option::ShowElapsedTime{true},
  option::ShowRemainingTime{true},
  option::ShowPercentage{true},
  option::FontStyles{std::vector<FontStyle>{FontStyle::bold}}
};

AP4_Result ProgressListener::OnProgress(unsigned int step, unsigned int total) {
  //printf("\r%d/%d", step, total);
  /*if (step != total) fprintf(stdout, "\r%d/%d", step, total);
  else fprintf(stdout, "\r%d/%d\n", step, total);
  fflush(stdout);*/
  show_console_cursor(false);
  if (step == 0 || step == 1) {
    bar.set_option(option::Completed{false});
    bar.set_option(option::SavedStartTime{false});
  }
  if (step % 5 == 0 || step == total) {
    bar.set_option(option::MaxProgress{total});
    bar.set_option(option::PostfixText{"Decrypting " + std::to_string(step) + "/" + std::to_string(total)});
    bar.set_progress(step);
  }
  if (step == total) {
    bar.set_option(option::Completed{true});
    show_console_cursor(true);
  }
  return AP4_SUCCESS;
}

class DecryptWorker : public Napi::AsyncWorker {
  private:
    AP4_ProtectionKeyMap key_map;
    std::string input_filename;
    std::string output_filename;
    bool show_progress;
    bool success = true;

  public:
    DecryptWorker(Napi::Function& callback, std::string inputFile, std::string outputFile, bool showProgress, std::map<std::string, std::string>& keys): 
      Napi::AsyncWorker(callback),
      input_filename(inputFile),
      output_filename(outputFile),
      show_progress(showProgress),
      key_map()
    { 
      std::map<std::string, std::string>::iterator it;      

      for (it = keys.begin(); it != keys.end(); it++) {
        unsigned char kid[16];
        unsigned char key[16];
        AP4_ParseHex(it->first.c_str(), kid, 16);
        AP4_ParseHex(it->second.c_str(), key, 16);
        key_map.SetKeyForKid(kid, key, 16);
      }
    }
    ~DecryptWorker() {}

    // Executed inside the worker-thread.
    // It is not safe to access JS engine data structure
    // here, so everything we need for input and output
    // should go on `this`.
    void Execute() {
      if (input_filename.empty()) {
        fprintf(stderr, "ERROR: missing input filename\n");
        success = false;
        return;
      }
      if (output_filename.empty()) {
        fprintf(stderr, "ERROR: missing output filename\n");
        success = false;
        return;
      }

      // create the input stream
      AP4_Result result;

      AP4_ByteStream* input = NULL;
      char* input_filename_string = new char[input_filename.length() + 1];
      strcpy(input_filename_string, input_filename.c_str());

      result = AP4_FileByteStream::Create(input_filename_string, AP4_FileByteStream::STREAM_MODE_READ, input);
      if (AP4_FAILED(result)) {
          fprintf(stderr, "ERROR: cannot open input file (%s) %d\n", input_filename_string, result);
          success = false;
          return;
      }

      // create the output stream
      AP4_ByteStream* output = NULL;
      char* output_filename_string = new char[output_filename.length() + 1];
      strcpy(output_filename_string, output_filename.c_str());

      result = AP4_FileByteStream::Create(output_filename_string, AP4_FileByteStream::STREAM_MODE_WRITE, output);
      if (AP4_FAILED(result)) {
          fprintf(stderr, "ERROR: cannot open output file (%s) %d\n", output_filename_string, result);
          success = false;
          return;
      }

      // create the decrypting processor
      AP4_Processor* processor = NULL;
      AP4_File* input_file = new AP4_File(*input);
      AP4_FtypAtom* ftyp = input_file->GetFileType();
      if (ftyp) {
          if (ftyp->GetMajorBrand() == AP4_OMA_DCF_BRAND_ODCF || ftyp->HasCompatibleBrand(AP4_OMA_DCF_BRAND_ODCF)) {
              processor = new AP4_OmaDcfDecryptingProcessor(&key_map);
          } else if (ftyp->GetMajorBrand() == AP4_MARLIN_BRAND_MGSV || ftyp->HasCompatibleBrand(AP4_MARLIN_BRAND_MGSV)) {
              processor = new AP4_MarlinIpmpDecryptingProcessor(&key_map);
          } else if (ftyp->GetMajorBrand() == AP4_PIFF_BRAND || ftyp->HasCompatibleBrand(AP4_PIFF_BRAND)) {
              processor = new AP4_CencDecryptingProcessor(&key_map);
          }
      }
      if (processor == NULL) {
          // no ftyp, look at the sample description of the tracks first
          AP4_Movie* movie = input_file->GetMovie();
          if (movie) {
              AP4_List<AP4_Track>& tracks = movie->GetTracks();
              for (unsigned int i=0; i<tracks.ItemCount(); i++) {
                  AP4_Track* track = NULL;
                  tracks.Get(i, track);
                  if (track) {
                      AP4_SampleDescription* sdesc = track->GetSampleDescription(0);
                      if (sdesc && sdesc->GetType() == AP4_SampleDescription::TYPE_PROTECTED) {
                          AP4_ProtectedSampleDescription* psdesc = AP4_DYNAMIC_CAST(AP4_ProtectedSampleDescription, sdesc);
                          if (psdesc) {
                              if (psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENC ||
                                  psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBC1 ||
                                  psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENS ||
                                  psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBCS) {
                                  processor = new AP4_CencDecryptingProcessor(&key_map);
                                  break;
                              }
                          }
                      }
                  }
              }
          }
      }
          
      // by default, try a standard decrypting processor
      if (processor == NULL) {
          processor = new AP4_StandardDecryptingProcessor(&key_map);
      }
      
      delete input_file;
      input_file = NULL;
      input->Seek(0);
      
      // process/decrypt the file
      ProgressListener listener;
      result = processor->Process(*input, *output, show_progress?&listener:NULL);
      if (AP4_FAILED(result)) {
        fprintf(stderr, "ERROR: failed to process the file (%d)\n", result);
        success = false;
      }

      // cleanup
      delete processor;
      input->Release();
      output->Release();
    }

    // Executed when the async work is complete
    // this function will be run inside the main event loop
    // so it is safe to use JS engine data again
    void OnOK() {
      Callback().Call({Napi::Boolean::New(Env(), success)});
    }

    void OnError() {
      bool success = false;
      Callback().Call({Napi::Boolean::New(Env(), success)});
    }
};

Napi::Value Decrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 4) {
    Napi::TypeError::New(env, "Wrong number of arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  if (!info[0].IsString() || !info[1].IsString() ||!info[2].IsObject() ||!info[3].IsBoolean() || !info[4].IsFunction()) {
    Napi::TypeError::New(env, "Wrong arguments")
        .ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::String inputFile = info[0].As<Napi::String>();
  Napi::String outputFile = info[1].As<Napi::String>();
  Napi::Object keysObject = info[2].As<Napi::Object>();
  Napi::Boolean showProgress = info[3].As<Napi::Boolean>();
  Napi::Function callback = info[4].As<Napi::Function>();

  std::map<std::string, std::string> keys;

  Napi::Array kids = keysObject.GetPropertyNames();
  for (uint32_t i = 0; i < kids.Length(); i++) {
    Napi::String hex_kid = kids.Get(i).ToString();
    Napi::String hex_key = keysObject.Get(hex_kid).ToString();
    keys[hex_kid.Utf8Value()] = hex_key.Utf8Value();
  }

  DecryptWorker* worker = new DecryptWorker(callback, inputFile.ToString().Utf8Value(), outputFile.ToString().Utf8Value(), showProgress.ToBoolean(), keys);
  worker->Queue();

  return env.Undefined();
}

Napi::Object Init (Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "decrypt"),
              Napi::Function::New(env, Decrypt));
  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);