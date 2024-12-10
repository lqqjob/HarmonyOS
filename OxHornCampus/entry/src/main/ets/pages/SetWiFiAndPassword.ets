import HomeMateAPSDK from 'package/src/main/ets/utils/HomeMateSDK'

@Builder
export function SetWiFiAndPasswordBuilder(name: string, param: Object) {
  SetWiFiAndPassword()
}

@Component
export struct SetWiFiAndPassword {
  private pageInfos: NavPathStack = new NavPathStack()
  private mac: string = ""
  private password?: string
  private intervalId?: number
  @State private ssid: string = ""
  @State private showCheckOnlineBtn: boolean = false

  build() {
    NavDestination() {
      Column() {
        Text() {
          Span("选择的WiFi：").fontSize(16).fontColor(Color.Black)
          Span(this.ssid).fontSize(16).fontColor(Color.Blue)
        }
        .fontSize(16)
        .fontColor(Color.Black)
        .width("100%")
        .height("40")
        .textAlign(TextAlign.Center)

        TextInput({ placeholder: "请输入密码" })
          .onChange((value: string) => {
            this.password = value;
          })

        Button() {
          Text('设置 WiFi 和密码')
            .fontSize(30)
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.White)
        }
        .type(ButtonType.Capsule)
        .margin({ top: 20 })
        .backgroundColor('#0dffb')
        .height('50')
        .padding({ left: 10, right: 10 })
        .onClick(() => {
          HomeMateAPSDK.setWiFi(this.ssid, this.password, (e, data) => {
            if (e !== undefined) {
              AlertDialog.show({
                title: e.name,
                message: e.message,
                autoCancel: true,
                confirm: {
                  value: '确认',
                  action: () => {

                  }
                }
              })
            } else {
              this.showCheckOnlineBtn = true
            }
          })
        })

        if (this.showCheckOnlineBtn == true) {
          Button() {
            Text('查询设备是否在线')
              .fontSize(30)
              .fontWeight(FontWeight.Bold)
              .fontColor(Color.White)
          }
          .type(ButtonType.Capsule)
          .margin({ top: 20 })
          .backgroundColor('#0dffb')
          .height('50')
          .padding({ left: 10, right: 10 })
          .onClick(() => {
            this.intervalId = setInterval(() => {
              this.checkDeviceIsOnline()
            }, 1000)
          })
        }
      }
      .width("100%")
      .align(Alignment.Center)
      .padding({ left: 15, right: 15 })
    }
    .title("设置 WiFi 名称和密码")
    .onReady((context: NavDestinationContext) => {
      this.pageInfos = context.pathStack
      let params = (this.pageInfos.getParamByName("SetWiFiAndPassword") as string[])[0]
      this.mac = params[0]
      this.ssid = params[1]
    })
  }

  checkDeviceIsOnline() {
    HomeMateAPSDK.checkOnlineForMac(this.mac, (e, data) => {
      if (e === undefined) {
        let online: number = data?.get("online") as number
        if (online == 1) { //在线，可以绑定设备
          clearInterval(this.intervalId)
          this.bindDevice()
        }
      }
    })
  }

  bindDevice() {
    HomeMateAPSDK.bindDeviceWithMac(this.mac, "test", "3d12c11f70a6400cb52363aed1e31631",
      "1f87ed0e0c2b44a58fca3193e94c1e99", (e, data) => {
        if (e === undefined) {
          let status = data?.get("status") as number
          if (status == 0) {
            AlertDialog.show({
              title: "HomeMateAP",
              message: "绑定成功",
              autoCancel: true,
              confirm: {
                value: '确认',
                action: () => {
                  this.pageInfos.clear()
                }
              }
            })
          }
        }
      });
  }
}