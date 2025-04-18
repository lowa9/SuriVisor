<template>
  <div class="settings">
    <h1>设置</h1>
    <v-row>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>系统设置</v-card-title>
          <v-card-text>
            <v-form>
              <v-text-field
                v-model="settings.apiEndpoint"
                label="API端点"
                outlined
              ></v-text-field>
              <v-select
                v-model="settings.refreshInterval"
                :items="refreshIntervals"
                label="数据刷新间隔"
                outlined
              ></v-select>
              <v-switch
                v-model="settings.darkMode"
                label="暗黑模式"
              ></v-switch>
              <v-btn color="primary" @click="saveSettings">保存设置</v-btn>
            </v-form>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>通知设置</v-card-title>
          <v-card-text>
            <v-form>
              <v-switch
                v-model="notifications.email"
                label="邮件通知"
              ></v-switch>
              <v-text-field
                v-model="notifications.emailAddress"
                label="邮箱地址"
                outlined
                :disabled="!notifications.email"
              ></v-text-field>
              <v-switch
                v-model="notifications.sms"
                label="短信通知"
              ></v-switch>
              <v-text-field
                v-model="notifications.phoneNumber"
                label="手机号码"
                outlined
                :disabled="!notifications.sms"
              ></v-text-field>
              <v-btn color="primary" @click="saveNotifications">保存通知设置</v-btn>
            </v-form>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script>
export default {
  name: 'Settings',
  data() {
    return {
      settings: {
        apiEndpoint: 'http://localhost:5000/api',
        refreshInterval: 60,
        darkMode: false
      },
      refreshIntervals: [
        { text: '30秒', value: 30 },
        { text: '1分钟', value: 60 },
        { text: '5分钟', value: 300 },
        { text: '15分钟', value: 900 },
        { text: '30分钟', value: 1800 }
      ],
      notifications: {
        email: false,
        emailAddress: '',
        sms: false,
        phoneNumber: ''
      }
    }
  },
  methods: {
    saveSettings() {
      // 保存系统设置
      console.log('保存系统设置:', this.settings)
    },
    saveNotifications() {
      // 保存通知设置
      console.log('保存通知设置:', this.notifications)
    }
  },
  mounted() {
    // 加载设置数据
  }
}
</script>