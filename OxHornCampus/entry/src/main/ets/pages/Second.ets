import { BusinessError } from '@kit.BasicServicesKit';
import HomeMateAPSDK from 'package/src/main/ets/utils/HomeMateSDK';
import { router } from '@kit.ArkUI';

@Builder
export function SecondBuilder(name: string, param: Object) {
  Second()
}

@Component
export  struct Second {
  @State message: string = 'Hi,here'
  @State deviceName: string = ''
  @State mac: string = ""
  pageInfos:NavPathStack = new NavPathStack()

  showAlert(e: BusinessError) {
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
  }

  build() {
    NavDestination() {
      Column({ space: 10 }) {
        Button() {
          Text('获取设备信息')
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
          HomeMateAPSDK.getDeviceInfo((e, data) => {
            if (e !== undefined) {
              this.showAlert(e)
            } else {
              if (data !== undefined) {
                this.deviceName = data?.get("deviceName") as string
                this.mac = data?.get("mac") as string
              }
            }
          })
        })

        if (this.deviceName.length > 0) {
          Row() {
            Text("设备名称：")
            Text(this.deviceName)
          }
        }
        if (this.deviceName.length > 0) {
          Row() {
            Text("mac：")
            Text(this.mac)
          }
          Button() {
            Text('获取WiFi列表')
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
            this.pageInfos.pushPathByName('GetWiFiListPage',this.mac)
          })
        }
      }
      .width('100%')
    }
    .title("获取设备信息")
    .onReady((context:NavDestinationContext) => {
      this.pageInfos = context.pathStack
    })
  }
}