//模块级编译构建任务脚本，开发者可以自定义相关任务和代码实现
import { hapTasks } from '@ohos/hvigor-ohos-plugin';

export default {
    system: hapTasks,  /* Built-in plugin of Hvigor. It cannot be modified. */
    plugins:[]         /* Custom plugin to extend the functionality of Hvigor. */
}
