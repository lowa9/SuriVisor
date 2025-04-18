<template>
  <div class="alerts">
    <h1>告警</h1>
    <v-row>
      <v-col cols="12">
        <v-card>
          <v-card-title>告警列表</v-card-title>
          <v-card-text>
            <v-data-table
              :headers="headers"
              :items="alerts"
              :items-per-page="5"
              class="elevation-1"
            >
              <template v-slot:item.severity="{ item }">
                <v-chip
                  :color="getSeverityColor(item.severity)"
                  dark
                >
                  {{ item.severity }}
                </v-chip>
              </template>
            </v-data-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script>
export default {
  name: 'Alerts',
  data() {
    return {
      headers: [
        { text: 'ID', value: 'id' },
        { text: '时间', value: 'timestamp' },
        { text: '严重程度', value: 'severity' },
        { text: '来源', value: 'source' },
        { text: '目标', value: 'destination' },
        { text: '描述', value: 'description' }
      ],
      alerts: [
        // 示例数据
        {
          id: 1,
          timestamp: '2023-05-01 10:30:45',
          severity: '高',
          source: '192.168.1.100',
          destination: '192.168.1.1',
          description: '可疑的SSH登录尝试'
        },
        {
          id: 2,
          timestamp: '2023-05-01 11:15:22',
          severity: '中',
          source: '192.168.1.105',
          destination: '8.8.8.8',
          description: '异常DNS请求'
        }
      ]
    }
  },
  methods: {
    getSeverityColor(severity) {
      if (severity === '高') return 'red'
      if (severity === '中') return 'orange'
      return 'green'
    }
  },
  mounted() {
    // 加载告警数据
  }
}
</script>