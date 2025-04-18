<template>
  <v-app>
    <v-app-bar app color="primary" dark>
      <v-app-bar-nav-icon @click="drawer = !drawer"></v-app-bar-nav-icon>
      <v-toolbar-title>SuriVisor 仪表盘</v-toolbar-title>
      <v-spacer></v-spacer>
    </v-app-bar>

    <v-navigation-drawer v-model="drawer" app>
      <v-list>
        <v-list-item
          v-for="(item, i) in menuItems"
          :key="i"
          :to="item.path"
          link
        >
          <v-list-item-icon>
            <v-icon>{{ item.icon }}</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title>{{ item.title }}</v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list>
    </v-navigation-drawer>

    <v-main>
      <v-container fluid>
        <router-view></router-view>
      </v-container>
    </v-main>

    <v-footer app>
      <span>&copy; {{ new Date().getFullYear() }} SuriVisor</span>
    </v-footer>
  </v-app>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      drawer: false,
      menuItems: [
        { title: '仪表盘', path: '/', icon: 'mdi-view-dashboard' },
        { title: '告警', path: '/alerts', icon: 'mdi-alert' },
        { title: '流量分析', path: '/traffic', icon: 'mdi-chart-line' },
        { title: '报告', path: '/reports', icon: 'mdi-file-document' },
        { title: '设置', path: '/settings', icon: 'mdi-cog' }
      ]
    }
  }
}
</script>