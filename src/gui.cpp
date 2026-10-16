#include "lgi/common/Lgi.h"
#include "lgi/common/TextLog.h"
#include "lgi/common/Json.h"
#include "lgi/common/Box.h"
#include "lgi/common/List.h"
#include "lgi/common/ListItemCheckBox.h"

#include "cpp-kasa/cpp-kasa.h"

enum Ctrls
{
	ID_LIST = 100,
	ID_LOG,
	ID_BOX,
};

auto appName = "kasaGui";

class App : public LWindow
{
	LTextLog *log = nullptr;
    LList *lst = nullptr;
	LBox *box = nullptr;
    LKasaProtocol kasa;

    struct KasaDeviceItem : public LListItem
    {
        LKasaDevice device;
        LListItemCheckBox *val = nullptr;

        KasaDeviceItem(const LKasaDevice &dev)
            : device(dev)
        {
            LJson json(device.Response);
            
            device.Name = json.Get("system.get_sysinfo.alias");
            if (!device.Name)
                device.Name = json.Get("system.get_sysinfo.system.alias");

            val = new LListItemCheckBox(this, 1, false);
        }

        const char *GetText(int col) override
        {
            switch (col)
            {
                case 0: return device.Name;
            }
            return nullptr;
        }
    };

public:
	App()
	{
		Name(appName);
		LRect r(0, 0, 1500, 1000);
		SetPos(r);
		MoveToCenter();
		SetQuitOnClose(true);
		
		if (Attach(nullptr))
		{
            AddView(box = new LBox(ID_BOX));
            box->AddView(lst = new LList(ID_LIST));
                lst->AddColumn("Name");
                lst->AddColumn("Switch");
            box->AddView(log = new LTextLog(ID_LOG));
			
			AttachChildren();
			Visible(true);

            kasa.Discover([this](const LKasaDevice &device)
                {
                    auto item = new KasaDeviceItem(device);
                    lst->Insert(item);
                    lst->ResizeColumnsToContent();
                });
		}
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
