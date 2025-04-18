<template>
  <div class="reports">
    <h1>报告</h1>
    <v-row>
      <v-col cols="12">
        <v-card>
          <v-card-title>报告列表</v-card-title>
          <v-card-text>
            <v-data-table
              :headers="headers"
              :items="reports"
              :items-per-page="5"
              class="elevation-1"
            >
              <template v-slot:item.actions="{ item }">
                <v-btn
                  small
                  color="primary"
                  @click="viewReport(item)"
                >
                  查看
                </v-btn>
                <v-btn
                  small
                  color="secondary"
                  class="ml-2"
                  @click="downloadReport(item)"
                >
                  下载
                </v-btn>
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
  name: 'Reports',
  data() {
    return {
      headers: [
        { text: '报告ID', value: 'id' },
        { text: '生成时间', value: 'timestamp' },
        { text: '报告类型', value: 'type' },
        { text: '描述', value: 'description' },
        { text: '操作', value: 'actions', sortable: false }
      ],
      reports: [
        // 示例数据
        {
          id: 1,
          timestamp: '2023-05-01',
          type: '安全审计',
          description: '网络安全月度审计报告'
        },
        {
          id: 2,
          timestamp: '2023-04-01',
          type: '流量分析',
          description: '网络流量月度分析报告'
        }
      ]
    }
  },
  methods: {
    viewReport(report) {
      // 查看报告详情
      console.log('查看报告:', report.id)
    },
    downloadReport(report) {
      // 下载报告
      console.log('下载报告:', report.id)
    }
  },
  mounted() {
    // 加载报告数据
  }
}
</script>