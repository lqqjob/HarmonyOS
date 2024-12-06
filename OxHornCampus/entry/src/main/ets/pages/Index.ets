import { router } from '@kit.ArkUI';
import HomeMateAPSDK from 'package/src/main/ets/utils/HomeMateSDK';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World'
  @State next: boolean = false
pageInfos:NavPathStack = new NavPathStack()
  build() {
    Navigation(this.pageInfos) {
      Column() {
        Button() {
          Text('连接设备')
            .fontSize(30)
            .fontWeight(FontWeight.Bold)
            .fontColor(Color.White)
        }
        .type(ButtonType.Capsule)
        .margin({ top: 20 })
        .backgroundColor('#0dffb')
        .width('40%')
        .height('50')
        .onClick(() => {
          HomeMateAPSDK.connect((e) => {
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
              this.next = true
            }
          });
        })

        if (this.next == true) {
          Button() {
            Text('下一步')
              .fontSize(30)
              .fontWeight(FontWeight.Bold)
              .fontColor(Color.White)
          }
          .type(ButtonType.Capsule)
          .margin({ top: 20 })
          .backgroundColor('#0dffb')
          .width('40%')
          .height('50')
          .onClick(() => {
            this.pageInfos.pushPathByName("Second",null)
          })
        }
      }
      .height('100%')

    }
    .hideBackButton(true)
    .title("HomeMateAPDemo")
  }
}