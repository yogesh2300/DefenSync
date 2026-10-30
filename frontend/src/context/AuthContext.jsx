import { createContext, useContext, useEffect, useState } from 'react'
import {
  getMe, login as apiLogin, logout as apiLogout, register as apiRegister, sendOtp as apiSendOtp,
  verifyOtp as apiVerifyOtp, verifyRegistration as apiVerifyRegistration,
} from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('defensync_token') || localStorage.getItem('cloudsync_token')
    if (!token) {
      setLoading(false)
      return
    }
    getMe()
      .then(setUser)
      .catch(() => apiLogout())
      .finally(() => setLoading(false))
  }, [])

  // Step 1 of 2: returns the OTP challenge; the user stays signed out.
  const login = (email, password) => apiLogin(email, password)

  const sendOtp = (challengeId, channel) => apiSendOtp(challengeId, channel)

  const loadProfile = async () => {
    const profile = await getMe()
    setUser(profile)
    return profile
  }

  // Step 2 of 2: only a verified code yields a session.
  const verifyOtp = async (challengeId, otp) => {
    await apiVerifyOtp(challengeId, otp)
    return loadProfile()
  }

  // Registration: the code is emailed first; the account exists (and signs in) only once it is verified.
  const register = (username, email, password) => apiRegister(username, email, password)

  const verifyRegistration = async (challengeId, otp) => {
    await apiVerifyRegistration(challengeId, otp)
    return loadProfile()
  }

  const logout = () => {
    apiLogout()
    setUser(null)
  }

  return (
    <AuthContext.Provider
      value={{ user, loading, login, sendOtp, verifyOtp, register, verifyRegistration, logout, isAdmin: user?.role?.toUpperCase() === 'ADMIN' }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
