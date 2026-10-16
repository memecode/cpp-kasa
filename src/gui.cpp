#include "lgi/common/Lgi.h"
#include "lgi/common/TextLog.h"
#include "lgi/common/Json.h"
#include "lgi/common/Box.h"
#include "lgi/common/List.h"
#include "lgi/common/ListItemCheckBox.h"
#include "lgi/common/OptionsFile.h"
#include "lgi/common/TableLayout.h"
#include "lgi/common/TextLabel.h"
#include "lgi/common/Edit.h"
#include "lgi/common/Menu.h"
#include "lgi/common/Button.h"
#include "lgi/common/XmlTreeUi.h"

#include "cpp-kasa/cpp-kasa.h"

#include <openssl/evp.h>

#include <string>
#include <vector>

#define OPT_User        "user"
#define OPT_Password    "password"

enum Ctrls
{
	ID_LIST = 100,
	ID_LOG,
	ID_BOX,
    ID_OPTIONS,
    ID_TABLE,
    ID_USER,
    ID_PASSWORD,
    ID_EXIT
};

auto appName = "kasaGui";

class OptionsDlg : public LDialog, public LXmlTreeUi
{
    LTableLayout *tbl = nullptr;
    LOptionsFile *options = nullptr;

public:
    OptionsDlg(LWindow *parent, LOptionsFile *opts)
        : options(opts)
    {
        SetParent(parent);
        Name("Options");
        LRect r(0, 0, 500, 130);
        SetPos(r);
        AddView(tbl = new LTableLayout(ID_TABLE));
        
        auto c = tbl->GetCell(0, 0);
        c->Add(new LTextLabel(ID_STATIC, 0, 0, -1, -1, "Kasa User:"));
        c->VerticalAlign(LCss::VerticalMiddle);
        c = tbl->GetCell(1, 0);
        c->Add(new LEdit(ID_USER));
        
        c = tbl->GetCell(0, 1);
        c->Add(new LTextLabel(ID_STATIC, 0, 0, -1, -1, "Password:"));
        c->VerticalAlign(LCss::VerticalMiddle);
        c = tbl->GetCell(1, 1);
        LEdit *pass;
        c->Add(pass = new LEdit(ID_PASSWORD));
        pass->Password(true);

        c = tbl->GetCell(0, 2, true, 2);
        c->TextAlign(LCss::AlignRight);
        c->Add(new LButton(IDOK, 0, 0, -1, -1, "Ok"));
        c->Add(new LButton(IDCANCEL, 0, 0, -1, -1, "Cancel"));

        Map(OPT_User, ID_USER, GV_STRING);
        Map(OPT_Password, ID_PASSWORD, GV_STRING);
        Convert(options, this, true);
    }

    int OnNotify(LViewI *Ctrl, const LNotification &n) override
    {
        switch (Ctrl->GetId())
        {
            case IDOK:
                Convert(options, this, false);
                EndModal(IDOK);
                return 1;
            case IDCANCEL:
                EndModal(IDCANCEL);
                return 1;
        }
        return 0;
    }
};

class App : public LWindow
{
	LTextLog *log = nullptr;
    LList *lst = nullptr;
	LBox *box = nullptr;
    LKasaProtocol kasa;
    LOptionsFile options;
    std::shared_ptr<int> lifetime = std::make_shared<int>(0);

    struct KasaDeviceItem : public LListItem
    {
        App *app = nullptr;
        LKasaDevice device;
        LListItemCheckBox *val = nullptr;
        LAutoPtr<LKasaProtocol> tapo;
        LAutoPtr<LKasaProtocol> legacy;
        bool relayState = false;
        bool switching = false;
        bool requestedState = false;
        std::shared_ptr<int> lifetime = std::make_shared<int>(0);

        void ShowResult(bool success, const LString &response)
        {
            std::string text = response.Get() ? response.Get() : "";
            std::weak_ptr<int> alive = lifetime;
            LAppInst->RunCallback([this, alive, success, text]()
            {
                if (alive.expired())
                    return;
                if (success)
                {
                    device.Response.Set(text.c_str());
                    LJson info(device.Response);
                    LString state = info.Get("result.device_on");
                    relayState = state.Equals("true", false) || state.Equals("1", false);
                    if (!switching)
                        val->Value(relayState);
                    LString nickname = info.Get("result.nickname");
                    device.Name.Empty();
                    if (nickname && nickname.Length() % 4 == 0)
                    {
                        std::vector<unsigned char> decoded(nickname.Length() / 4 * 3 + 1);
                        int length = EVP_DecodeBlock(decoded.data(),
                            (const unsigned char *)nickname.Get(), (int)nickname.Length());
                        if (length > 0)
                        {
                            if (nickname.Get()[nickname.Length() - 1] == '=')
                                length--;
                            if (nickname.Length() > 1 && nickname.Get()[nickname.Length() - 2] == '=')
                                length--;
                            if (length > 0)
                                device.Name.Set((const char *)decoded.data(), length);
                        }
                    }
                    if (!device.Name)
                        device.Name.Set(device.Ip.Get());
                }
                else
                    device.Name.Printf("Error: %s", text.c_str());
                Update();
                app->lst->ResizeColumnsToContent();
            }, _FL);
        }

        KasaDeviceItem(App *a, const LKasaDevice &dev)
            : app(a)
        {
            device.Ip.Set(dev.Ip.Get());
            device.Name.Set(dev.Name.Get());
            device.Response.Set(dev.Response.Get());
            LJson json(device.Response);
            
            device.Name = json.Get("system.get_sysinfo.alias");
            if (!device.Name)
                device.Name = json.Get("system.get_sysinfo.system.alias");
            if (!device.Name)
            {
                // Maybe its a Tapo device?
                if (tapo.Reset(new LKasaProtocol(app->kasa)))
                {
                    printf("Attempting to connect to Tapo device at IP: %s\n", device.Ip.Get());
                    device.Name = "..connecting..";
                    bool queued = tapo->ConnectSmart(device, [this](bool status, const LString &str)
                    {
                        if (!status)
                        {
                            ShowResult(false, str);
                            return;
                        }
                        if (!tapo->GetDeviceInfo([this](bool success, const LString &response)
                        {
                            ShowResult(success, response);
                        }))
                            ShowResult(false, LString("Device info request was not queued"));
                    });
                    if (!queued)
                        device.Name = "Error: Connection was not queued";
                }
            }

            LString state = json.Get("system.get_sysinfo.relay_state");
            if (!state)
                state = json.Get("system.get_sysinfo.system.relay_state");
            relayState = state.Equals("1", false);
            val = new LListItemCheckBox(this, 1, relayState);
        }

        ~KasaDeviceItem() override
        {
            tapo.Reset();
            legacy.Reset();
            lifetime.reset();
        }

        const char *GetText(int col) override
        {
            switch (col)
            {
                case 0: return device.Name;
            }
            return nullptr;
        }

        void OnColumnNotify(int col, int64 data) override
        {
            if (col != 1)
            {
                LListItem::OnColumnNotify(col, data);
                return;
            }
            if (switching)
            {
                val->Value(requestedState);
                Update();
                return;
            }

            bool on = data != 0;
            requestedState = on;
            switching = true;
            Update();
            auto complete = [this, on](bool success, const LString &response)
            {
                if (success && !tapo)
                {
                    LJson result(response);
                    LString code = result.Get("system.set_relay_state.err_code");
                    if (code && !code.Equals("0", false))
                        success = false;
                }
                std::string text = response.Get() ? response.Get() : "";
                std::weak_ptr<int> alive = lifetime;
                LAppInst->RunCallback([this, alive, on, success, text]()
                {
                    if (alive.expired())
                        return;
                    switching = false;
                    if (success)
                        relayState = on;
                    else
                    {
                        LString error;
                        error.Printf("Failed to switch %s: %s", device.Ip.Get(), text.c_str());
                        app->log->Name(error);
                    }
                    val->Value(relayState);
                    Update();
                }, _FL);
            };

            if (tapo)
            {
                if (!tapo->SetDeviceOn(on, complete))
                    complete(false, LString("Switch command was not queued"));
            }
            else
            {
                if (!legacy)
                    legacy.Reset(new LKasaProtocol(app->kasa));
                if (legacy->IsConnected())
                {
                    if (!legacy->SetRelayState(on, complete))
                        complete(false, LString("Switch command was not queued"));
                }
                else if (!legacy->Connect(device.Ip, [this, on, complete](bool success, const LString &response)
                {
                    if (!success)
                        complete(false, response);
                    else if (!legacy->SetRelayState(on, complete))
                        complete(false, LString("Switch command was not queued"));
                }))
                    complete(false, LString("Connection was not queued"));
            }
        }
    };

    void ApplyOptions()
    {
        LVariant user, pass;
        if (options.GetValue(OPT_User, user) &&
            options.GetValue(OPT_Password, pass))
        {
            kasa.SetCredentials(user.Str(), pass.Str());
        }
    }

public:
	App()
        : options(LOptionsFile::PortableMode, appName)
	{
		Name(appName);
		LRect r(0, 0, 1500, 1000);
		SetPos(r);
		MoveToCenter();
		SetQuitOnClose(true);
		
        options.SerializeFile(false);

		if (!Attach(nullptr))
            return;

        if (Menu = new LMenu(appName))
        {
            Menu->Attach(this);
            auto file = Menu->AppendSub("File");
            file->AppendItem("Options", ID_OPTIONS);
            file->AppendItem("Exit", ID_EXIT, true, -1, "Ctrl+W");
        }

        AddView(box = new LBox(ID_BOX));
        box->AddView(lst = new LList(ID_LIST));
            lst->AddColumn("Name");
            lst->AddColumn("Switch");
        box->AddView(log = new LTextLog(ID_LOG));
        
        AttachChildren();
        Visible(true);

        ApplyOptions();

        std::weak_ptr<int> alive = lifetime;
        kasa.Discover([this, alive](const LKasaDevice &device)
            {
                std::string ip = device.Ip.Get() ? device.Ip.Get() : "";
                std::string response = device.Response.Get() ? device.Response.Get() : "";
                LAppInst->RunCallback([this, alive, ip, response]()
                {
                    if (alive.expired())
                        return;
                    LKasaDevice copy;
                    copy.Ip.Set(ip.c_str());
                    copy.Response.Set(response.c_str());
                    auto item = new KasaDeviceItem(this, copy);
                    lst->Insert(item);
                    lst->ResizeColumnsToContent();
                }, _FL);
            });
	}

    ~App()
    {
        lifetime.reset();
        options.SerializeFile(true);
    }

    int OnNotify(LViewI *Ctrl, const LNotification &n) override
    {
        switch (Ctrl->GetId())
        {
            case ID_LIST:
            {
                switch (n.Type)
                {
                    case LNotifyItemSelect:
                    {
                        LArray<KasaDeviceItem*> sel;
                        if (lst->GetSelection(sel) && sel.Length() == 1)
                        {
                            LJson j(sel[0]->device.Response);
                            log->Name(j.GetJson());
                        }
                        break;
                    }
                }
                break;
            }
        }
        return 0;
    }

    int OnCommand(int Cmd, int Event, OsView Handle) override
    {
        switch (Cmd)
        {
            case ID_OPTIONS:
            {
                auto Opts = new OptionsDlg(this, &options);

                Opts->DoModal([this](auto dlg, auto code)
                {
                    if (code == IDOK)
                    {
                        // send the user/pass to the kasa protocol
                        ApplyOptions();
                    }
                });
                return 0;
            }
            case ID_EXIT:
            {
                LCloseApp();
                return 0;
            }
        }

        return LWindow::OnCommand(Cmd, Event, Handle);
    }
};

int LgiMain(OsAppArguments &AppArgs)
{
	LApp app(AppArgs, "kasa-gui");
	if (app.IsOk())
	{
		app.AppWnd = new App;
		app.Run();
	}
	return 0;
}
