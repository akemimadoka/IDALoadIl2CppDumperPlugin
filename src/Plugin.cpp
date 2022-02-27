#include <simdjson.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <bytes.hpp>

#include <charconv>
#include <fstream>
#include <format>

#define ACTION_NAME "IDALoadIl2CppDumperPlugin::Load"
#define LOG_PREFIX ACTION_NAME ": "

namespace
{
    class IDALoadIl2CppDumperLoadAction : public action_handler_t
    {
    public:
        int idaapi activate(action_activation_ctx_t *ctx) override
        {
            const auto declFilename = ask_file(false, "*.h", "Select il2cpp.h to load, this is optional");
            if (declFilename)
            {
                msg(LOG_PREFIX "Parsing declaration file from path %s\n", declFilename);

                std::ifstream declFile(declFilename, std::ios_base::ate);
                const auto size = declFile.tellg();
                std::string content(size, 0);
                declFile.seekg(0);
                declFile.read(content.data(), size);
                declFile.close();

                if (parse_decls(nullptr, content.c_str(), msg, 0) != 0)
                {
                    msg(LOG_PREFIX "Cannot parse il2cpp.h\n");
                }
            }

            const auto filename = ask_file(false, "*.json", "Select JSON file to load");
            if (!filename)
            {
                msg(LOG_PREFIX "No file selected\n");
                return 0;
            }

            msg(LOG_PREFIX "Parsing JSON file from path %s\n", filename);

            const auto imageBase = get_imagebase();

            simdjson::dom::parser parser;
            simdjson::dom::element doc = parser.load(filename);

            if (!doc.is_object())
            {
                msg(LOG_PREFIX "Document is not an object\n");
                return 0;
            }

            if (const auto addresses = doc["Addresses"].get_array(); addresses.error() == simdjson::SUCCESS)
            {
                msg(LOG_PREFIX "Found %zu addresses\n", addresses.size());

                for (const auto elem : addresses)
                {
                    const auto addr = elem.get_uint64().value() + imageBase;

                    if (get_func(addr))
                    {
                        msg(LOG_PREFIX "Function at 0x%016" PRIx64 " already exists\n", addr);
                        continue;
                    }

                    const auto flags = get_flags(addr);
                    if (!is_code(flags))
                    {
                        if (create_insn(addr) == 0)
                        {
                            msg(LOG_PREFIX "Cannot convert data at 0x%016" PRIx64 " to code\n", addr);
                            continue;
                        }
                    }
                    if (!add_func(addr))
                    {
                        msg(LOG_PREFIX "Failed to add function at 0x%016" PRIx64 "\n", addr);
                    }
                }
            }
            else
            {
                msg(LOG_PREFIX "Document does not contain Addresses\n");
            }

            if (const auto scriptMethods = doc["ScriptMethod"].get_array(); scriptMethods.error() == simdjson::SUCCESS)
            {
                msg(LOG_PREFIX "Found %zu script methods\n", scriptMethods.size());

                for (const auto elem : scriptMethods)
                {
                    const auto address = elem["Address"].get_uint64().value() + imageBase;
                    const auto name = elem["Name"].get_string().value();
                    const auto signature = elem["Signature"].get_string().value();
                    const auto typeSignature = elem["TypeSignature"].get_string().value();

                    if (!set_name(address, name.data(), SN_NOWARN | SN_NOCHECK))
                    {
                        msg(LOG_PREFIX "Failed to set method name at 0x%016" PRIx64 " to %s\n", address, name.data());
                        continue;
                    }

                    if (!apply_cdecl(nullptr, address, signature.data()))
                    {
                        msg(LOG_PREFIX "Cannot apply signature at 0x%016" PRIx64 " to %s\n", address, signature.data());
                        continue;
                    }

                    if (!set_cmt(address, typeSignature.data(), true))
                    {
                        msg(LOG_PREFIX "Cannot add comment at 0x%016" PRIx64 " to %s\n", address, typeSignature.data());
                    }
                }
            }
            else
            {
                msg(LOG_PREFIX "Document does not contain ScriptMethod\n");
            }

            if (const auto scriptStrings = doc["ScriptString"].get_array(); scriptStrings.error() == simdjson::SUCCESS)
            {
                msg(LOG_PREFIX "Found %zu script strings\n", scriptStrings.size());

                std::size_t index = 0;
                constexpr const char Prefix[] = "String_";
                // 去除结尾 0
                constexpr std::size_t PrefixSize = std::size(Prefix) - 1;
                // 足以表示 std::uint64_t 的最大值
                constexpr auto BufferSize = PrefixSize + 21;
                std::string name = Prefix;
                name.reserve(BufferSize);

                for (const auto elem : scriptStrings)
                {
                    const auto address = elem["Address"].get_uint64().value() + imageBase;
                    const auto value = elem["Value"].get_string().value();

                    name.resize(BufferSize);
                    if (const auto [end, ec] = std::to_chars(name.data() + PrefixSize, name.data() + BufferSize, index++); ec != std::errc{}) [[unlikely]]
                    {
                        msg(LOG_PREFIX "Cannot create string name, this is a bug, please file an issue to the author\n");
                        continue;
                    }
                    else
                    {
                        name.resize(end - name.data());
                    }

                    if (!set_name(address, name.c_str(), SN_NOWARN))
                    {
                        msg(LOG_PREFIX "Cannot set string name at 0x%016" PRIx64 " to %s\n", address, name.c_str());
                        continue;
                    }

                    if (!set_cmt(address, value.data(), true))
                    {
                        msg(LOG_PREFIX "Cannot set string value at 0x%016" PRIx64 " (%s) to comment\n", address, value.data());
                    }
                }
            }
            else
            {
                msg(LOG_PREFIX "Document does not contain ScriptString\n");
            }

            simdjson::dom::array scriptMetadatas;
            if (doc["ScriptMetadata"].get(scriptMetadatas))
            {
                msg(LOG_PREFIX "Found %zu script metadatas\n", scriptMetadatas.size());

                for (const auto elem : scriptMetadatas)
                {
                    const auto address = elem["Address"].get_uint64().value() + imageBase;
                    const auto name = elem["Name"].get_string().value();
                    const auto signature = elem["Signature"].get_string();

                    if (!set_name(address, name.data(), SN_NOWARN))
                    {
                        msg(LOG_PREFIX "Cannot set metadata name at 0x%016" PRIx64 " to %s\n", address, name.data());
                        continue;
                    }

                    if (signature.error() == simdjson::SUCCESS)
                    {
                        if (!apply_cdecl(nullptr, address, signature.value_unsafe().data()))
                        {
                            msg(LOG_PREFIX "Cannot apply metadata signature at 0x%016" PRIx64 " to %s\n", address, signature.value_unsafe().data());
                        }
                    }
                }
            }
            else
            {
                msg(LOG_PREFIX "Document does not contain ScriptMetadata\n");
            }

            if (const auto scriptMetadataMethods = doc["ScriptMetadataMethod"].get_array(); scriptMetadataMethods.error() == simdjson::SUCCESS)
            {
                msg(LOG_PREFIX "Found %zu script metadata methods\n", scriptMetadataMethods.size());

                for (const auto elem : scriptMetadataMethods)
                {
                    const auto address = elem["Address"].get_uint64().value() + imageBase;
                    const auto name = elem["MethodAddress"].get_string().value();
                    const auto methodAddress = elem["MethodAddress"].get_uint64().value() + imageBase;

                    if (!set_name(address, name.data(), SN_NOWARN | SN_NOCHECK))
                    {
                        msg(LOG_PREFIX "Cannot set metadata method name at 0x%016" PRIx64 " to %s\n", address, name.data());
                        continue;
                    }

                    char methodAddressStr[17];
                    if (const auto [end, ec] = std::to_chars(methodAddressStr, std::end(methodAddressStr), methodAddress, 16); ec != std::errc{}) [[unlikely]]
                    {
                        msg(LOG_PREFIX "Cannot create method address string, this is a bug, please file an issue to the author\n");
                        continue;
                    }
                    else
                    {
                        *end = 0;
                    }

                    if (!set_cmt(address, methodAddressStr, true))
                    {
                        msg(LOG_PREFIX "Cannot set metadata method comment at 0x%016" PRIx64 " to %s\n", address, methodAddressStr);
                    }
                }
            }
            else
            {
                msg(LOG_PREFIX "Document does not contain ScriptMetadataMethod\n");
            }

            return 1;
        }

        action_state_t idaapi update(action_update_ctx_t *ctx) override
        {
            return AST_ENABLE_ALWAYS;
        }
    };

    class IDALoadIl2CppDumperPlugin : public plugmod_t
    {
    public:
        IDALoadIl2CppDumperPlugin()
            : m_ActionDesc(ACTION_DESC_LITERAL_PLUGMOD(ACTION_NAME, "Load Il2Cpp Dumper JSON", &m_Action, this, nullptr, nullptr, -1))
        {
        }

        bool RegisterAction()
        {
            return register_action(m_ActionDesc) && attach_action_to_menu("File/Load Il2CppDumper JSON", ACTION_NAME, SETMENU_APP);
        }

        bool idaapi run(size_t arg) override
        {
            msg("IDALoadIl2CppDumperPlugin::run\n");
            return true;
        }

    private:
        IDALoadIl2CppDumperLoadAction m_Action;
        const action_desc_t m_ActionDesc;
    };

    plugmod_t *idaapi init()
    {
        const auto plugin = new IDALoadIl2CppDumperPlugin();
        if (!plugin->RegisterAction())
        {
            delete plugin;
            return nullptr;
        }

        return plugin;
    }
}

plugin_t PLUGIN{
    .version = IDP_INTERFACE_VERSION,
    .flags = PLUGIN_MOD | PLUGIN_MULTI,
    .init = init,
    .term = nullptr,
    .run = nullptr,
    .comment = nullptr,
    .help = nullptr,
    .wanted_name = "IDALoadIl2CppDumperPlugin",
    .wanted_hotkey = nullptr,
};
