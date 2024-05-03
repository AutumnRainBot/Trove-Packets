#include "includes.h"
#include"detours.h"
#include<string>
#include<iomanip>

#pragma comment(lib, "Ws2_32.lib")
#define WSAAPI                  FAR PASCAL

//Constant
HMODULE myhmod;
FILE* pFile = nullptr;
HWND hwndOutput = nullptr;
HWND hwndInput = nullptr;
HWND hwndInputLen = nullptr;
#define WSAEVENT HANDLE
struct sockaddr_in clientService;

//backup in case
SOCKET ConnectSocket = INVALID_SOCKET;

//Proto functions
typedef int (WINAPI* SendPtr)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* WSASendPtr)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, LPDWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* ConnectCustom)(SOCKET s, const SOCKADDR* sAddr, int nameLen);
typedef int (WINAPI* SendToCustom)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int ToLen);
typedef int (WINAPI* CustomGetaddrinfo)(PCSTR Host, PCSTR port, const ADDRINFOA* pHints, PADDRINFOA* ppResult);

//Lib
HMODULE hLib = LoadLibrary("WS2_32.dll");

//get the internal function 
SendPtr pSend = (SendPtr)GetProcAddress(hLib, "send");
ConnectCustom pConnect = (ConnectCustom)GetProcAddress(hLib, "connect");
WSASendPtr pWsaSend = (WSASendPtr)GetProcAddress(hLib, "WSASend");
SendToCustom pSendTo = (SendToCustom)GetProcAddress(hLib, "sendto");
CustomGetaddrinfo pGetAddrInfo = (CustomGetaddrinfo)GetProcAddress(hLib, "getaddrinfo");

int SERVER_IP;
int PORT;

int TO_SERVER_IP;
int TO_PORT;

PCSTR WSA_TO_SERVER_IP = "";
int WSA_TO_PORT;


extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

Present oPresent;
HWND window = NULL;
WNDPROC oWndProc;
ID3D11Device* pDevice = NULL;
ID3D11DeviceContext* pContext = NULL;
ID3D11RenderTargetView* mainRenderTargetView;

// Input and Output buffers
static char Input[10000] = "Enter your packet here :p";;
static char Output[10000] = "Packets will be displayed here :p";

//Toggles
bool SendToggle = false;
bool SendToToggle = false;
bool WSASendToggle = true;
bool BlockPacketToggle = false;
bool TranslateToAOB = false;

void InitImGui()
{
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags = ImGuiConfigFlags_NoMouseCursorChange;
	ImGui_ImplWin32_Init(window);
	ImGui_ImplDX11_Init(pDevice, pContext);
}

void OutputPacketText(const char text[])
{
    // Check if there's enough space in the Output buffer to append the text
    if (strlen(Output) + strlen(text) < sizeof(Output)) {
        strncat(Output, text, sizeof(Output) - strlen(Output) - 1);
    }
}



//For send() hook it to read the buffer and print it  
int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    int result = pSend(s, buf, len, flags);
    // Check if it's checked
    if (SendToggle == true) {
        OutputPacketText("=======================================\n");
        OutputPacketText("Send() Sent Data : \n");

        // Print buffer content as an array of bytes
        if (TranslateToAOB) {
            OutputPacketText("Buffer content (hex): ");
            for (int i = 0; i < len; ++i)
            {
                // Convert each byte to its hexadecimal representation
                char hex[4];
                sprintf_s(hex, "%02X ", static_cast<unsigned char>(buf[i]));
                OutputPacketText(hex);
            }
        }
        else
        {
            OutputPacketText("Buffer : \n");
            OutputPacketText(buf);
        }
        OutputPacketText("\n");
    }
    return result;
}


char InjectedBuffer[5000] = "";
int InjectedLen = 0;

//For WSASEnd() hook it to read the buffer and print it                    
int WSAAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, LPDWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int result = 0;
    

    if (WSASendToggle == true) {

        /*
        if (InjectedBuffer != "") {
            OutputPacketText(InjectedBuffer);
        }
        */
        if (lpBuffers[0].len> 200) //
        {
            OutputPacketText("=======================================\n");
            OutputPacketText("WSASend() Sent Data : \n");

            for (DWORD i = 0; i < dwBufferCount; ++i)
            {
                const char* bufferContent = reinterpret_cast<const char*>(lpBuffers[i].buf);
                DWORD bufferLength = lpBuffers[i].len;
                if (TranslateToAOB) {
                    // Print buffer content as an array of bytes
                    OutputPacketText("Buffer content (hex): ");
                    for (DWORD j = 0; j < bufferLength; ++j)
                    {
                        // Convert each byte to its hexadecimal representation
                        char hex[4];
                        sprintf_s(hex, "%02X ", static_cast<unsigned char>(bufferContent[j]));
                        OutputPacketText(hex);
                    }
                }
                else
                {
                    OutputPacketText("Buffer : \n");
                    OutputPacketText(bufferContent);
                }
            }

            OutputPacketText("\n");
        }
        
    }


    if (BlockPacketToggle == false) {
        if (lpBuffers[0].len >= InjectedLen && InjectedLen != 0) //if packet size is greater than our packet and is not empty then we inject
        {
            lpBuffers[0].len = InjectedLen;
            lpBuffers[0].buf = const_cast<char*>(InjectedBuffer);
            InjectedLen = 0;
            OutputPacketText("");
        }
        result = pWsaSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    }


    return result;
}

// For sendto() hook it to read the buffer and print it
int WSAAPI MySendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    // Call the original sendto() function
    int result = pSendTo(s, buf, len, flags, to, tolen);

    // Check if it's checked
    if (SendToToggle == true) {
        OutputPacketText("=======================================\n");
        // Extracting the IP and port of the receiver
        const sockaddr_in* clientService = reinterpret_cast<const sockaddr_in*>(to);
        unsigned long ipAddress = clientService->sin_addr.s_addr;

        std::string MyIpAddress = std::to_string(ipAddress);
        const char* IpConstChar = MyIpAddress.c_str();

        TO_SERVER_IP = static_cast<int>(ipAddress);
        TO_PORT = static_cast<int>(ntohs(clientService->sin_port));

        if (result >= 0)
        {
            OutputPacketText("SendTo() Sent Data (hex): \n");

            // Print buffer content as an array of bytes
            if (TranslateToAOB) {
                OutputPacketText("Buffer content (hex): \n");
                for (int i = 0; i < len; ++i)
                {
                    // Convert each byte to its hexadecimal representation
                    char hex[4];
                    sprintf_s(hex, "%02X ", static_cast<unsigned char>(buf[i]));
                    OutputPacketText(hex);
                }
            }
            else
            {
                OutputPacketText("Buffer : \n");
                OutputPacketText(buf);
            }
            OutputPacketText("\n");
        }

        OutputPacketText("\n");
    }

    return result;
}


//Hook the connect to get the IP and the PORT of the server for (send , recv)
int WSAAPI MyConnect(SOCKET s, const SOCKADDR* sAddr, int nameLen)
{
    // Assuming sAddr is of type SOCKADDR_IN
    const sockaddr_in* clientService = reinterpret_cast<const sockaddr_in*>(sAddr);
    unsigned long ipAddress = clientService->sin_addr.s_addr;

    std::string MyIpAddress = std::to_string(ipAddress);
    const char* IpConstChar = MyIpAddress.c_str();

    SERVER_IP = static_cast<int>(ipAddress);
    PORT = static_cast<int>(ntohs(clientService->sin_port));

    struct in_addr ipAddr;
    ipAddr.s_addr = htonl(ipAddress);

    // Convert to string and print
    std::string ipAddresss = inet_ntoa(ipAddr);


    OutputPacketText("\n");
    OutputPacketText("IP address being used is: ");
    OutputPacketText(ipAddresss.c_str());
    OutputPacketText("\n");

    OutputPacketText("Port being used is: ");
    OutputPacketText(std::to_string(ntohs(clientService->sin_port)).c_str());
    OutputPacketText("\n");

    return pConnect(s, sAddr, nameLen);
}

int WSAAPI MyGetAddrinfo(PCSTR Host, PCSTR port, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{

    OutputPacketText("Host : ");
    OutputPacketText((const char*)Host);
    OutputPacketText("\n");


    OutputPacketText("Port : ");
    OutputPacketText((const char*)port);
    OutputPacketText("\n");

    WSA_TO_SERVER_IP = (const char*)Host;
    WSA_TO_PORT = static_cast<int>(PORT);

    return pGetAddrInfo(Host, port, pHints, ppResult);
}


LRESULT __stdcall WndProc(const HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	if (true && ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam))
		return true;

	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

bool init = false;
HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{

    

	if (!init)
	{
		if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)& pDevice)))
		{
			pDevice->GetImmediateContext(&pContext);
			DXGI_SWAP_CHAIN_DESC sd;
			pSwapChain->GetDesc(&sd);
			window = sd.OutputWindow;
			ID3D11Texture2D* pBackBuffer;
			pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)& pBackBuffer);
			pDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
			pBackBuffer->Release();
			oWndProc = (WNDPROC)SetWindowLongPtr(window, GWLP_WNDPROC, (LONG_PTR)WndProc);
			InitImGui();
			init = true;
		}

		else
			return oPresent(pSwapChain, SyncInterval, Flags);
	}
	


	

	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	ImGui::SetNextWindowSize(ImVec2(500, 350));

	if (ImGui::Begin("Packet logger by RainBot , Discord : accesslist", NULL, ImGuiWindowFlags_NoResize)) {


		//Output packet
		if (ImGui::TreeNode("Output packets")) {

			static ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput;
			ImGui::InputTextMultiline("##source", Output, IM_ARRAYSIZE(Output), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), flags);
			ImGui::TreePop();
			//clear output button
			if (ImGui::Button("Clear output")) {
				memset(Output, 0, sizeof(Output));
			}
		}

		//Input packet
		if (ImGui::TreeNode("Input packets")) {
			static ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput;
			ImGui::InputTextMultiline("##source", Input, IM_ARRAYSIZE(Input), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), flags);
			ImGui::TreePop();

			// Send packet button
			if (ImGui::Button("Send packet")) {
                if (WSASendToggle) {
                    char TempPacket[5000];
                    strcpy(TempPacket,Input);//We take our input and we put in out TempPacket

                    //Translate from aob packet to its original form
                    if (TranslateToAOB) {
                        std::string inputText(TempPacket);
                        inputText.erase(std::remove_if(inputText.begin(), inputText.end(), ::isspace), inputText.end());
                        std::string asciiText;
                        for (size_t i = 0; i < inputText.length(); i += 2) {
                            std::string hexValue = inputText.substr(i, 2);
                            char asciiChar = static_cast<char>(std::stoi(hexValue, nullptr, 16));
                            asciiText += asciiChar;
                        }
                        const char* finaltest = asciiText.c_str();
                        strcpy(TempPacket, finaltest);
                    }

                    //packet injecting logic
                    const char* sendData = TempPacket;
                    int sendDataLength = strlen(sendData);

                    //On finished preparing we inject
                    strcpy(InjectedBuffer, sendData);
                    InjectedLen = sendDataLength;
                    OutputPacketText("Injected packet successfully !");
                }

			}

			
			ImGui::Checkbox("Send", &SendToggle);
			ImGui::Checkbox("SendTo", &SendToToggle);
			ImGui::Checkbox("WSASend", &WSASendToggle);
			ImGui::Checkbox("Block Packets", &BlockPacketToggle);
			ImGui::Checkbox("AOB Translate", &TranslateToAOB);
		}

	}



	ImGui::End();

	ImGui::Render();

	pContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	return oPresent(pSwapChain, SyncInterval, Flags);
}

DWORD WINAPI MainThread(LPVOID lpReserved)
{
	bool init_hook = false;
	do
	{
		if (kiero::init(kiero::RenderType::D3D11) == kiero::Status::Success)
		{
			kiero::bind(8, (void**)& oPresent, hkPresent);
			init_hook = true;
		}
	} while (!init_hook);
	return TRUE;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hMod);
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)pSend, (PVOID)MySend);
        DetourAttach(&(PVOID&)pConnect, (PVOID)MyConnect);
        DetourAttach(&(PVOID&)pWsaSend, (PVOID)MyWSASend);
        DetourAttach(&(PVOID&)pSendTo, (PVOID)MySendTo);
        DetourAttach(&(PVOID&)pGetAddrInfo, (PVOID)MyGetAddrinfo);

        DetourTransactionCommit();
		CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
		break;
	case DLL_PROCESS_DETACH:
		kiero::shutdown();
		break;
	}
	return TRUE;
}
