<template>
  <div class="dashboard">
    <h1>SuriVisor 仪表盘</h1>
    <v-row>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>告警概览</v-card-title>
          <v-card-text>
            <v-list>
              <v-list-item>
                <v-list-item-title>高危告警: 0</v-list-item-title>
              </v-list-item>
              <v-list-item>
                <v-list-item-title>中危告警: 0</v-list-item-title>
              </v-list-item>
              <v-list-item>
                <v-list-item-title>低危告警: 0</v-list-item-title>
              </v-list-item>
            </v-list>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>流量统计</v-card-title>
          <v-card-text>
            <p>暂无数据</p>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script>
export default {
  name: 'Dashboard',
  data() {
    return {
      // 仪表盘数据
    }
  },
  mounted() {
    // 加载仪表盘数据
  }
}
</script>