import { createStore } from 'vuex'
import axios from 'axios'

export default createStore({
  state: {
    alerts: [],
    trafficData: [],
    reports: [],
    loading: false,
    error: null
  },
  getters: {
    getAlerts: state => state.alerts,
    getTrafficData: state => state.trafficData,
    getReports: state => state.reports,
    isLoading: state => state.loading,
    hasError: state => state.error
  },
  mutations: {
    SET_ALERTS(state, alerts) {
      state.alerts = alerts
    },
    SET_TRAFFIC_DATA(state, data) {
      state.trafficData = data
    },
    SET_REPORTS(state, reports) {
      state.reports = reports
    },
    SET_LOADING(state, status) {
      state.loading = status
    },
    SET_ERROR(state, error) {
      state.error = error
    }
  },
  actions: {
    async fetchAlerts({ commit }) {
      commit('SET_LOADING', true)
      try {
        const response = await axios.get('/api/alerts')
        commit('SET_ALERTS', response.data)
        commit('SET_ERROR', null)
      } catch (error) {
        commit('SET_ERROR', error.message)
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async fetchTrafficData({ commit }) {
      commit('SET_LOADING', true)
      try {
        const response = await axios.get('/api/traffic')
        commit('SET_TRAFFIC_DATA', response.data)
        commit('SET_ERROR', null)
      } catch (error) {
        commit('SET_ERROR', error.message)
      } finally {
        commit('SET_LOADING', false)
      }
    },
    async fetchReports({ commit }) {
      commit('SET_LOADING', true)
      try {
        const response = await axios.get('/api/reports')
        commit('SET_REPORTS', response.data)
        commit('SET_ERROR', null)
      } catch (error) {
        commit('SET_ERROR', error.message)
      } finally {
        commit('SET_LOADING', false)
      }
    }
  },
  modules: {
  }
})