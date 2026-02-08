// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('redis');
const axios = require('axios');
const cheerio = require('cheerio');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Configuração do Redis
const redisClient = createClient({
  url: process.env.REDIS_URL || 'rediss://b585d0c34b3f41e0a278bf29653560b3:bakaiwz78@redis.shardatabases.app:6379',
  socket: {
    tls: true,
    rejectUnauthorized: false
  }
});

(async () => {
  try {
    await redisClient.connect();
    console.log('✅ Conectado ao Redis Cloud');
  } catch (error) {
    console.error('❌ Erro ao conectar ao Redis:', error);
  }
})();

// Configurações das APIs
const CONFIG = {
  // Sala do Futuro (CMSP)
  SALA_FUTURO: {
    BASE_URL: process.env.SALA_FUTURO_URL || 'https://api.saladofuturo.com',
    AUTH_ENDPOINT: '/auth/login',
    ROOMS_ENDPOINT: '/api/rooms',
    ACTIVITIES_ENDPOINT: '/api/activities'
  },
  
  // Khan Academy
  KHAN: {
    BASE_URL: 'https://pt.khanacademy.org',
    LOGIN_ENDPOINT: '/login',
    API_BASE: '/api/internal',
    GRAPHQL_ENDPOINT: '/graphql'
  },
  
  // Network Khan
  NETWORK: {
    VERSION: '2.0.0',
    AUTHOR: 'Bakai'
  }
};

// Headers padrão
const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'application/json, text/html, */*',
  'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive'
};

// Middleware
app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

if (NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: 'Muitas requisições. Tente novamente mais tarde.'
  }
});
app.use('/api/', limiter);

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = process.env.JWT_EXPIRY || '24h';

// Helper Functions
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      name: user.name || user.username,
      type: 'network_khan'
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Authentication Middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Token de autenticação não fornecido'
    });
  }
  
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({
      success: false,
      message: 'Token inválido ou expirado'
    });
  }
  
  req.user = decoded;
  next();
};

// ========== ROTAS PRINCIPAIS ==========

// Health Check
app.get('/api/health', async (req, res) => {
  try {
    const redisStatus = redisClient.isOpen ? 'connected' : 'disconnected';
    
    res.json({
      success: true,
      service: 'Network Khan',
      version: CONFIG.NETWORK.VERSION,
      author: CONFIG.NETWORK.AUTHOR,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      services: {
        redis: redisStatus,
        api: 'running'
      },
      environment: NODE_ENV
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Health check failed'
    });
  }
});

// ========== SALA DO FUTURO ==========

// Login na Sala do Futuro
app.post('/api/sala-futuro/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'RA e senha são obrigatórios'
      });
    }
    
    // Simulação do login na Sala do Futuro
    // Em produção, você usaria a API real
    const isSimulation = process.env.NODE_ENV !== 'production' || req.headers['x-use-simulation'] === 'true';
    
    if (isSimulation) {
      // Simulação para desenvolvimento
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Verificar se é um RA válido (simulação)
      if (!username.match(/^\d{9,}$/)) {
        return res.status(401).json({
          success: false,
          message: 'RA inválido. Use apenas números.'
        });
      }
      
      // Gerar token simulado
      const token = crypto.randomBytes(32).toString('hex');
      const user = {
        id: `sf_${username}`,
        username: username,
        name: `Aluno ${username}`,
        ra: username,
        role: 'student',
        level: 'medio', // ensino médio
        hasKhan: Math.random() > 0.3, // 70% de chance de ter Khan
        classrooms: [
          { id: 'sala1', name: 'Matemática 2º Ano', teacher: 'Prof. Silva' },
          { id: 'sala2', name: 'Português 2º Ano', teacher: 'Prof. Santos' },
          { id: 'sala3', name: 'Ciências 2º Ano', teacher: 'Prof. Costa' }
        ]
      };
      
      // Salvar no Redis
      await redisClient.setEx(`sala_futuro:${username}:token`, 86400, token);
      await redisClient.setEx(`sala_futuro:user:${username}`, 86400, JSON.stringify(user));
      
      // Gerar token do Network Khan
      const networkToken = generateToken(user);
      
      res.json({
        success: true,
        message: 'Login realizado com sucesso na Sala do Futuro',
        token: networkToken,
        user: user,
        sala_futuro_token: token
      });
      
    } else {
      // Implementação real da API da Sala do Futuro
      // Esta é uma estrutura de exemplo - ajuste conforme a API real
      const response = await axios.post(`${CONFIG.SALA_FUTURO.BASE_URL}${CONFIG.SALA_FUTURO.AUTH_ENDPOINT}`, {
        ra: username,
        password: password,
        platform: 'web'
      }, {
        headers: HEADERS
      });
      
      if (response.data.success) {
        const userData = response.data.user;
        const token = response.data.token;
        
        // Buscar salas do usuário
        const roomsResponse = await axios.get(`${CONFIG.SALA_FUTURO.BASE_URL}${CONFIG.SALA_FUTURO.ROOMS_ENDPOINT}`, {
          headers: { ...HEADERS, 'Authorization': `Bearer ${token}` }
        });
        
        const user = {
          id: userData.id,
          username: userData.ra || userData.username,
          name: userData.name,
          ra: userData.ra,
          role: userData.role,
          level: userData.grade_level || 'medio',
          hasKhan: false, // Será verificado nas próximas etapas
          classrooms: roomsResponse.data.rooms || []
        };
        
        // Salvar no Redis
        await redisClient.setEx(`sala_futuro:${username}:token`, 86400, token);
        await redisClient.setEx(`sala_futuro:user:${username}`, 86400, JSON.stringify(user));
        
        // Gerar token do Network Khan
        const networkToken = generateToken(user);
        
        res.json({
          success: true,
          message: 'Login realizado com sucesso na Sala do Futuro',
          token: networkToken,
          user: user,
          sala_futuro_token: token
        });
        
      } else {
        throw new Error(response.data.message || 'Credenciais inválidas');
      }
    }
    
  } catch (error) {
    console.error('Sala Futuro login error:', error.message);
    
    if (error.response?.status === 401) {
      return res.status(401).json({
        success: false,
        message: 'RA ou senha incorretos'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Erro ao conectar com a Sala do Futuro: ' + error.message
    });
  }
});

// Verificar se tem Khan Academy nas salas
app.get('/api/sala-futuro/check-khan', authenticate, async (req, res) => {
  try {
    const username = req.user.username;
    
    // Buscar dados do usuário
    const userData = await redisClient.get(`sala_futuro:user:${username}`);
    if (!userData) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado. Faça login novamente.'
      });
    }
    
    const user = JSON.parse(userData);
    
    // Buscar atividades nas salas
    let hasKhan = false;
    let khanActivities = [];
    let isEnsinoMedio = user.level === 'medio';
    
    // Simulação de busca por atividades do Khan
    if (user.hasKhan) {
      hasKhan = true;
      khanActivities = [
        {
          id: 'khan_math_1',
          title: 'Khan Academy - Matemática',
          description: 'Atividades de matemática do Khan Academy',
          subject: 'Matemática',
          grade: '2º Ano EM',
          url: 'https://pt.khanacademy.org/math',
          status: 'active'
        },
        {
          id: 'khan_science_1',
          title: 'Khan Academy - Ciências',
          description: 'Atividades de ciências do Khan Academy',
          subject: 'Ciências',
          grade: '2º Ano EM',
          url: 'https://pt.khanacademy.org/science',
          status: 'active'
        }
      ];
    }
    
    // Verificar se é ensino médio
    if (!isEnsinoMedio) {
      return res.json({
        success: false,
        message: 'Você não tem Khan Academy disponível ou não é do ensino médio.',
        hasKhan: false,
        isEnsinoMedio: false,
        userLevel: user.level
      });
    }
    
    // Verificar se tem Khan
    if (!hasKhan) {
      return res.json({
        success: false,
        message: 'Você não tem Khan Academy disponível em suas salas.',
        hasKhan: false,
        isEnsinoMedio: true,
        khanActivities: []
      });
    }
    
    res.json({
      success: true,
      message: 'Khan Academy encontrado!',
      hasKhan: true,
      isEnsinoMedio: true,
      khanActivities: khanActivities,
      user: {
        name: user.name,
        ra: user.ra,
        level: user.level
      }
    });
    
  } catch (error) {
    console.error('Check Khan error:', error);
    res.status(500).json({
      success: false,
      message: 'Erro ao verificar Khan Academy: ' + error.message
    });
  }
});

// ========== KHAN ACADEMY ==========

// Login no Khan Academy
app.post('/api/khan/login', authenticate, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email e senha do Khan são obrigatórios'
      });
    }
    
    // Simulação para desenvolvimento
    const isSimulation = process.env.NODE_ENV !== 'production' || req.headers['x-use-simulation'] === 'true';
    
    if (isSimulation) {
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulação de credenciais válidas
      if (email === 'demo@khan.com' && password === 'demo123') {
        const khanToken = crypto.randomBytes(32).toString('hex');
        const kaid = `kaid_${crypto.randomBytes(8).toString('hex')}`;
        
        // Salvar sessão
        await redisClient.setEx(`khan:${req.user.id}:session`, 86400, JSON.stringify({
          email: email,
          kaid: kaid,
          token: khanToken,
          loggedAt: new Date().toISOString()
        }));
        
        res.json({
          success: true,
          message: 'Login no Khan Academy realizado!',
          kaid: kaid,
          user: {
            email: email,
            kaid: kaid,
            name: 'Usuário Demo Khan'
          }
        });
      } else {
        throw new Error('Credenciais do Khan Academy inválidas');
      }
    } else {
      // Implementação real do login no Khan Academy
      // Obter página de login para pegar cookies e CSRF
      const initialResponse = await axios.get(`${CONFIG.KHAN.BASE_URL}${CONFIG.KHAN.LOGIN_ENDPOINT}`, {
        headers: HEADERS
      });
      
      const cookies = initialResponse.headers['set-cookie'];
      const $ = cheerio.load(initialResponse.data);
      const csrfToken = $('input[name="csrfmiddlewaretoken"]').val();
      
      if (!csrfToken) {
        throw new Error('Não foi possível obter token CSRF');
      }
      
      // Fazer login
      const loginResponse = await axios.post(
        `${CONFIG.KHAN.BASE_URL}${CONFIG.KHAN.LOGIN_ENDPOINT}`,
        new URLSearchParams({
          identifier: email,
          password: password,
          csrfmiddlewaretoken: csrfToken
        }).toString(),
        {
          headers: {
            ...HEADERS,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookies.join('; ')
          },
          maxRedirects: 5,
          validateStatus: null
        }
      );
      
      // Verificar se login foi bem sucedido
      if (loginResponse.status === 200 && loginResponse.request?.res?.responseUrl?.includes('profile')) {
        const kaidMatch = loginResponse.headers['set-cookie']?.find(c => c.includes('kaid='))?.match(/kaid=([^;]+)/);
        const kaid = kaidMatch ? kaidMatch[1] : null;
        
        if (kaid) {
          // Salvar sessão
          await redisClient.setEx(`khan:${req.user.id}:session`, 86400, JSON.stringify({
            email: email,
            kaid: kaid,
            cookies: loginResponse.headers['set-cookie'],
            loggedAt: new Date().toISOString()
          }));
          
          res.json({
            success: true,
            message: 'Login no Khan Academy realizado!',
            kaid: kaid,
            user: { email: email, kaid: kaid }
          });
        } else {
          throw new Error('Não foi possível obter KAID');
        }
      } else {
        throw new Error('Credenciais do Khan Academy inválidas');
      }
    }
    
  } catch (error) {
    console.error('Khan login error:', error.message);
    res.status(401).json({
      success: false,
      message: 'Falha no login do Khan: ' + error.message
    });
  }
});

// Iniciar Processo Automático
app.post('/api/process/start', authenticate, async (req, res) => {
  try {
    const { khanActivityId, strategy = 'auto', estimatedTime = 10 } = req.body;
    
    if (!khanActivityId) {
      return res.status(400).json({
        success: false,
        message: 'ID da atividade do Khan é obrigatório'
      });
    }
    
    // Criar job de processamento
    const jobId = `job_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const jobData = {
      id: jobId,
      userId: req.user.id,
      username: req.user.username,
      khanActivityId: khanActivityId,
      strategy: strategy,
      estimatedTime: parseInt(estimatedTime),
      status: 'starting',
      progress: 0,
      currentStep: 'Inicializando...',
      startedAt: new Date().toISOString(),
      logs: [`Job iniciado em ${new Date().toISOString()}`],
      errors: [],
      results: {
        totalQuestions: 0,
        answered: 0,
        correct: 0,
        wrong: 0
      }
    };
    
    // Salvar job no Redis
    await redisClient.setEx(`process:job:${jobId}`, 3600, JSON.stringify(jobData));
    await redisClient.lPush(`user:${req.user.id}:jobs`, jobId);
    await redisClient.lTrim(`user:${req.user.id}:jobs`, 0, 49);
    
    // Iniciar processamento em background
    startBackgroundProcess(jobId, jobData);
    
    res.json({
      success: true,
      message: 'Processo automático iniciado!',
      jobId: jobId,
      job: {
        id: jobId,
        status: jobData.status,
        progress: jobData.progress,
        currentStep: jobData.currentStep,
        estimatedTime: jobData.estimatedTime,
        startedAt: jobData.startedAt
      }
    });
    
  } catch (error) {
    console.error('Start process error:', error);
    res.status(500).json({
      success: false,
      message: 'Erro ao iniciar processo: ' + error.message
    });
  }
});

// Verificar Status do Processo
app.get('/api/process/status/:jobId', authenticate, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    const jobData = await redisClient.get(`process:job:${jobId}`);
    
    if (!jobData) {
      return res.status(404).json({
        success: false,
        message: 'Processo não encontrado'
      });
    }
    
    const job = JSON.parse(jobData);
    
    // Verificar permissão
    if (job.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Acesso não autorizado a este processo'
      });
    }
    
    res.json({
      success: true,
      job: job
    });
    
  } catch (error) {
    console.error('Status error:', error);
    res.status(500).json({
      success: false,
      message: 'Erro ao verificar status'
    });
  }
});

// Cancelar Processo
app.post('/api/process/cancel/:jobId', authenticate, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    const jobData = await redisClient.get(`process:job:${jobId}`);
    
    if (!jobData) {
      return res.status(404).json({
        success: false,
        message: 'Processo não encontrado'
      });
    }
    
    const job = JSON.parse(jobData);
    
    if (job.userId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Acesso não autorizado'
      });
    }
    
    // Atualizar status para cancelado
    job.status = 'cancelled';
    job.endedAt = new Date().toISOString();
    job.logs.push(`Processo cancelado em ${job.endedAt}`);
    
    await redisClient.setEx(`process:job:${jobId}`, 3600, JSON.stringify(job));
    
    res.json({
      success: true,
      message: 'Processo cancelado com sucesso',
      job: job
    });
    
  } catch (error) {
    console.error('Cancel error:', error);
    res.status(500).json({
      success: false,
      message: 'Erro ao cancelar processo'
    });
  }
});

// ========== FUNÇÃO DE PROCESSAMENTO EM BACKGROUND ==========

async function startBackgroundProcess(jobId, jobData) {
  try {
    // Atualizar status para rodando
    jobData.status = 'running';
    jobData.progress = 5;
    jobData.currentStep = 'Conectando ao Khan Academy...';
    jobData.logs.push('Iniciando conexão com Khan Academy');
    await redisClient.setEx(`process:job:${jobId}`, 3600, JSON.stringify(jobData));
    
    // Simular etapas do processo
    const steps = [
      'Conectando ao Khan Academy...',
      'Buscando atividades...',
      'Analisando questões...',
      'Resolvendo problemas matemáticos...',
      'Verificando respostas...',
      'Enviando respostas...',
      'Finalizando processo...'
    ];
    
    const totalSteps = steps.length;
    
    for (let i = 0; i < totalSteps; i++) {
      // Simular tempo entre etapas (1-3 segundos)
      await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 1000));
      
      // Atualizar progresso
      const progress = Math.min(5 + ((i + 1) / totalSteps * 90), 95);
      jobData.progress = Math.round(progress);
      jobData.currentStep = steps[i];
      jobData.logs.push(`Etapa ${i + 1}/${totalSteps}: ${steps[i]}`);
      
      // Simular resultados
      if (i >= 3) {
        jobData.results.totalQuestions = 10;
        jobData.results.answered = Math.min(10, Math.floor((i - 2) * 2.5));
        jobData.results.correct = Math.floor(jobData.re
