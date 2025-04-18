<template>
  <div class="traffic">
    <h1>流量分析</h1>
    <v-row>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>流量趋势</v-card-title>
          <v-card-text>
            <p>暂无数据</p>
            <!-- 这里将来会添加流量趋势图表 -->
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card>
          <v-card-title>协议分布</v-card-title>
          <v-card-text>
            <p>暂无数据</p>
            <!-- 这里将来会添加协议分布图表 -->
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12">
        <v-card>
          <v-card-title>流量详情</v-card-title>
          <v-card-text>
            <v-data-table
              :headers="headers"
              :items="trafficData"
              :items-per-page="5"
              class="elevation-1"
            ></v-data-table>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script>
export default {
  name: 'Traffic',
  data() {
    return {
      headers: [
        { text: '时间', value: 'timestamp' },
        { text: '源IP', value: 'source' },
        { text: '目标IP', value: 'destination' },
        { text: '协议', value: 'protocol' },
        { text: '数据量', value: 'bytes' }
      ],
      trafficData: [
        // 示例数据
        {
          timestamp: '2023-05-01 10:30:45',
          source: '192.168.1.100',
          destination: '192.168.1.1',
          protocol: 'TCP',
          bytes: 1240
        },
        {
          timestamp: '2023-05-01 11:15:22',
          source: '192.168.1.105',
          destination: '8.8.8.8',
          protocol: 'UDP',
          bytes: 512
        }
      ]
    }
  },
  mounted() {
    // 加载流量数据
  }
}
</script>