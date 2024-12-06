import HomeMateAPSDK from 'package/src/main/ets/utils/HomeMateSDK';
import { HashMap } from '@kit.ArkTS';


@Builder
export function GetWiFiListPageBuilder(name: string, param: Object) {
  GetWiFiListPage()
}

@Component
export struct GetWiFiListPage {
  pageInfos: NavPathStack = new NavPathStack()
  @State wifiList: Array<HashMap<string, string | number> | undefined> = new Array()
  private mac: string = ''

  build() {
    NavDestination() {
      Column({ space: 10 }) {
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
          HomeMateAPSDK.getWiFiList((e, data) => {
            if (e === undefined) {
              this.wifiList.push(data)
            }
          })
        })

        if (this.wifiList.length > 0) {
          List() {
            ForEach(this.wifiList, (item: HashMap<string, string | number>) => {
              ListItem() {
                Text(item.get("ssid") as string)
                  .width("100%")
                  .height(50)
              }
              .onClick(() => {
                this.pageInfos.pushPathByName("SetWiFiAndPassword", [this.mac, item.get('ssid')])
              })
            })
          }
          .divider({ strokeWidth: 0.5 })
          .padding({ left: 16, right: 16 })
          .width("100%")
          .height("90%")
        }
      }
    }
    .title("获取 WiFi 列表")
    .onReady((context: NavDestinationContext) => {
      this.pageInfos = context.pathStack
      let temp: string[] = this.pageInfos.getParamByName("GetWiFiListPage") as string[]
      this.mac = temp[0]
    })

  }
}