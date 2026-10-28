import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

import { requireAuth, generateCustomToken } from './src/middleware/auth.ts';
import { db } from './src/db/index.ts';
import { checks, users, installments } from './src/db/schema.ts';
import { eq, and, desc } from 'drizzle-orm';

const app = express();
const PORT = 3000;

app.use(express.json());

// Password hashing helper
const SALT = 'check-insurance-system-salt';
const hashPassword = (password: string) => {
  return crypto.createHash('sha256').update(password + SALT).digest('hex');
};

// --- Custom Auth Endpoints ---

// Register Custom User
app.post('/api/auth/register', async (req, res) => {
  const { email, password, displayName } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'لطفاً ایمیل و رمز عبور را وارد کنید.' });
    return;
  }

  if (password.length < 6) {
    res.status(400).json({ error: 'رمز عبور باید حداقل ۶ کاراکتر باشد.' });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const existingUsers = await db.select().from(users).where(eq(users.email, cleanEmail));
    if (existingUsers.length > 0) {
      res.status(400).json({ error: 'کاربری با این ایمیل قبلاً ثبت‌نام کرده است.' });
      return;
    }

    const hashedPassword = hashPassword(password);
    const [newUser] = await db.insert(users).values({
      uid: 'custom:' + cleanEmail,
      email: cleanEmail,
      displayName: displayName ? displayName.trim() : cleanEmail.split('@')[0],
      password: hashedPassword
    }).returning();

    const token = generateCustomToken(newUser.id, newUser.email);
    res.status(201).json({
      token,
      user: {
        username: newUser.displayName || newUser.email.split('@')[0],
        email: newUser.email
      }
    });
  } catch (err) {
    console.error('Error registering custom user:', err);
    res.status(500).json({ error: 'خطا در ثبت‌نام کاربر در پایگاه داده' });
  }
});

// Login Custom User
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'لطفاً ایمیل و رمز عبور را وارد کنید.' });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    const existingUsers = await db.select().from(users).where(eq(users.email, cleanEmail));
    if (existingUsers.length === 0) {
      res.status(400).json({ error: 'ایمیل یا رمز عبور اشتباه است.' });
      return;
    }

    const user = existingUsers[0];
    if (!user.password) {
      res.status(400).json({ error: 'این حساب با گوگل ساخته شده است. لطفاً از طریق گوگل وارد شوید.' });
      return;
    }

    const hashedPassword = hashPassword(password);
    if (user.password !== hashedPassword) {
      res.status(400).json({ error: 'ایمیل یا رمز عبور اشتباه است.' });
      return;
    }

    const token = generateCustomToken(user.id, user.email);
    res.json({
      token,
      user: {
        username: user.displayName || user.email.split('@')[0],
        email: user.email
      }
    });
  } catch (err) {
    console.error('Error logging in custom user:', err);
    res.status(500).json({ error: 'خطا در ورود به سیستم' });
  }
});

// --- API Endpoints ---

// Get Checks for user
app.get('/api/checks', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  try {
    const userChecks = await db.select()
      .from(checks)
      .where(eq(checks.userId, dbUser.id))
      .orderBy(desc(checks.createdAt));
    res.json(userChecks);
  } catch (err) {
    console.error('Error fetching checks:', err);
    res.status(500).json({ error: 'خطا در دریافت اطلاعات از پایگاه داده' });
  }
});

// Add New Check
app.post('/api/checks', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { insuredName, checkOwner, contactNumber, checkNumber, bankName, insuranceType, date, amount, isCleared, vehicleInfo, description } = req.body;

  if (!insuredName || !checkOwner || !checkNumber || !insuranceType || !date || amount === undefined) {
    res.status(400).json({ error: 'لطفاً تمامی فیلدهای الزامی را پر کنید.' });
    return;
  }

  const parsedAmount = Number(amount);
  if (isNaN(parsedAmount) || parsedAmount < 0) {
    res.status(400).json({ error: 'مبلغ چک نامعتبر است.' });
    return;
  }

  const newCheckId = crypto.randomUUID();
  const newCheck = {
    id: newCheckId,
    userId: dbUser.id,
    insuredName: insuredName.trim(),
    checkOwner: checkOwner.trim(),
    contactNumber: (contactNumber || '').trim(),
    checkNumber: checkNumber.trim(),
    bankName: (bankName || '').trim(),
    insuranceType: insuranceType.trim(),
    date: date.trim(),
    amount: parsedAmount,
    isCleared: !!isCleared,
    vehicleInfo: (vehicleInfo || '').trim(),
    description: (description || '').trim(),
    createdAt: new Date().toISOString()
  };

  try {
    await db.insert(checks).values(newCheck);
    res.status(201).json(newCheck);
  } catch (err) {
    console.error('Error creating check:', err);
    res.status(500).json({ error: 'خطا در ثبت چک در پایگاه داده' });
  }
});

// Toggle Clearance Status
app.patch('/api/checks/:id/toggle', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;

  try {
    const existingChecks = await db.select()
      .from(checks)
      .where(and(eq(checks.id, id), eq(checks.userId, dbUser.id)));

    if (existingChecks.length === 0) {
      res.status(404).json({ error: 'چک مورد نظر پیدا نشد.' });
      return;
    }

    const checkToUpdate = existingChecks[0];
    const updated = await db.update(checks)
      .set({ isCleared: !checkToUpdate.isCleared })
      .where(eq(checks.id, id))
      .returning();

    res.json(updated[0]);
  } catch (err) {
    console.error('Error toggling clearance:', err);
    res.status(500).json({ error: 'خطا در بروزرسانی وضعیت چک' });
  }
});

// Update Check Details
app.put('/api/checks/:id', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;
  const { insuredName, checkOwner, contactNumber, checkNumber, bankName, insuranceType, date, amount, isCleared, vehicleInfo, description } = req.body;

  if (!insuredName || !checkOwner || !checkNumber || !insuranceType || !date || amount === undefined) {
    res.status(400).json({ error: 'لطفاً تمامی فیلدهای الزامی را پر کنید.' });
    return;
  }

  const parsedAmount = Number(amount);
  if (isNaN(parsedAmount) || parsedAmount < 0) {
    res.status(400).json({ error: 'مبلغ چک نامعتبر است.' });
    return;
  }

  try {
    const existingChecks = await db.select()
      .from(checks)
      .where(and(eq(checks.id, id), eq(checks.userId, dbUser.id)));

    if (existingChecks.length === 0) {
      res.status(404).json({ error: 'چک مورد نظر پیدا نشد.' });
      return;
    }

    const updated = await db.update(checks)
      .set({
        insuredName: insuredName.trim(),
        checkOwner: checkOwner.trim(),
        contactNumber: (contactNumber || '').trim(),
        checkNumber: checkNumber.trim(),
        bankName: (bankName || '').trim(),
        insuranceType: insuranceType.trim(),
        date: date.trim(),
        amount: parsedAmount,
        isCleared: !!isCleared,
        vehicleInfo: (vehicleInfo || '').trim(),
        description: (description || '').trim()
      })
      .where(eq(checks.id, id))
      .returning();

    res.json(updated[0]);
  } catch (err) {
    console.error('Error updating check:', err);
    res.status(500).json({ error: 'خطا در ویرایش اطلاعات چک' });
  }
});

// Delete Check
app.delete('/api/checks/:id', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;

  try {
    const existingChecks = await db.select()
      .from(checks)
      .where(and(eq(checks.id, id), eq(checks.userId, dbUser.id)));

    if (existingChecks.length === 0) {
      res.status(404).json({ error: 'چک مورد نظر پیدا نشد.' });
      return;
    }

    await db.delete(checks).where(eq(checks.id, id));
    res.json({ success: true, message: 'چک با موفقیت حذف شد.' });
  } catch (err) {
    console.error('Error deleting check:', err);
    res.status(500).json({ error: 'خطا در حذف چک' });
  }
});

// --- Installments API Endpoints ---

// Get Installment Plans
app.get('/api/installments', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  try {
    const userInstallments = await db.select()
      .from(installments)
      .where(eq(installments.userId, dbUser.id))
      .orderBy(desc(installments.createdAt));

    const formatted = userInstallments.map(item => ({
      ...item,
      schedules: JSON.parse(item.schedulesJson || '[]')
    }));

    res.json(formatted);
  } catch (err) {
    console.error('Error fetching installments:', err);
    res.status(500).json({ error: 'خطا در دریافت لیست حساب‌های باز و اقساط' });
  }
});

// Add New Installment Plan
app.post('/api/installments', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { insuredName, policyNumber, contactNumber, insuranceType, totalAmount, installmentCount, issueDate, startDate, intervalMonths, schedules, vehicleInfo, description } = req.body;

  if (!insuredName || !policyNumber || !insuranceType || !startDate || !totalAmount || !installmentCount) {
    res.status(400).json({ error: 'لطفاً تمامی فیلدهای الزامی را پر کنید.' });
    return;
  }

  const parsedAmount = Number(totalAmount);
  const parsedCount = Number(installmentCount);
  if (isNaN(parsedAmount) || parsedAmount < 0 || isNaN(parsedCount) || parsedCount < 1) {
    res.status(400).json({ error: 'اطلاعات مبلغ یا تعداد اقساط نامعتبر است.' });
    return;
  }

  const newId = crypto.randomUUID();
  const schedulesJson = JSON.stringify(schedules || []);

  const newRecord = {
    id: newId,
    userId: dbUser.id,
    insuredName: insuredName.trim(),
    policyNumber: policyNumber.trim(),
    contactNumber: (contactNumber || '').trim(),
    insuranceType: insuranceType.trim(),
    totalAmount: parsedAmount,
    installmentCount: parsedCount,
    issueDate: (issueDate || '').trim(),
    startDate: startDate.trim(),
    intervalMonths: Number(intervalMonths || 1),
    schedulesJson,
    vehicleInfo: (vehicleInfo || '').trim(),
    description: (description || '').trim(),
    createdAt: new Date().toISOString()
  };

  try {
    await db.insert(installments).values(newRecord);
    res.status(201).json({
      ...newRecord,
      schedules: schedules || []
    });
  } catch (err) {
    console.error('Error creating installment plan:', err);
    res.status(500).json({ error: 'خطا در ثبت حساب باز و اقساط' });
  }
});

// Toggle Specific Installment Item Status
app.patch('/api/installments/:id/toggle-item', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;
  const { itemId } = req.body;

  try {
    const existing = await db.select()
      .from(installments)
      .where(and(eq(installments.id, id), eq(installments.userId, dbUser.id)));

    if (existing.length === 0) {
      res.status(404).json({ error: 'پرونده اقساط مورد نظر یافت نشد.' });
      return;
    }

    const plan = existing[0];
    const currentSchedules: any[] = JSON.parse(plan.schedulesJson || '[]');
    const updatedSchedules = currentSchedules.map(item => {
      if (item.id === itemId) {
        return {
          ...item,
          isPaid: !item.isPaid,
          paidAt: !item.isPaid ? new Date().toISOString() : undefined
        };
      }
      return item;
    });

    const updated = await db.update(installments)
      .set({ schedulesJson: JSON.stringify(updatedSchedules) })
      .where(eq(installments.id, id))
      .returning();

    res.json({
      ...updated[0],
      schedules: updatedSchedules
    });
  } catch (err) {
    console.error('Error toggling installment item:', err);
    res.status(500).json({ error: 'خطا در تغییر وضعیت قسط' });
  }
});

// Toggle All Items (Clear/Unclear entire installment plan)
app.patch('/api/installments/:id/toggle-all', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;
  const { targetState } = req.body;

  try {
    const existing = await db.select()
      .from(installments)
      .where(and(eq(installments.id, id), eq(installments.userId, dbUser.id)));

    if (existing.length === 0) {
      res.status(404).json({ error: 'پرونده اقساط مورد نظر یافت نشد.' });
      return;
    }

    const plan = existing[0];
    const currentSchedules: any[] = JSON.parse(plan.schedulesJson || '[]');
    
    const isAllPaid = currentSchedules.every(s => s.isPaid);
    const newState = typeof targetState === 'boolean' ? targetState : !isAllPaid;

    const updatedSchedules = currentSchedules.map(item => ({
      ...item,
      isPaid: newState,
      paidAt: newState ? (item.paidAt || new Date().toISOString()) : undefined
    }));

    const updated = await db.update(installments)
      .set({ schedulesJson: JSON.stringify(updatedSchedules) })
      .where(eq(installments.id, id))
      .returning();

    res.json({
      ...updated[0],
      schedules: updatedSchedules
    });
  } catch (err) {
    console.error('Error toggling all installment items:', err);
    res.status(500).json({ error: 'خطا در تغییر وضعیت کلی اقساط' });
  }
});

// Update Installment Plan
app.put('/api/installments/:id', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;
  const { insuredName, policyNumber, contactNumber, insuranceType, totalAmount, installmentCount, issueDate, startDate, intervalMonths, schedules, vehicleInfo, description } = req.body;

  try {
    const existing = await db.select()
      .from(installments)
      .where(and(eq(installments.id, id), eq(installments.userId, dbUser.id)));

    if (existing.length === 0) {
      res.status(404).json({ error: 'پرونده اقساط مورد نظر یافت نشد.' });
      return;
    }

    const schedulesJson = JSON.stringify(schedules || []);
    const updated = await db.update(installments)
      .set({
        insuredName: insuredName.trim(),
        policyNumber: policyNumber.trim(),
        contactNumber: (contactNumber || '').trim(),
        insuranceType: insuranceType.trim(),
        totalAmount: Number(totalAmount),
        installmentCount: Number(installmentCount),
        issueDate: (issueDate || '').trim(),
        startDate: startDate.trim(),
        intervalMonths: Number(intervalMonths || 1),
        schedulesJson,
        vehicleInfo: (vehicleInfo || '').trim(),
        description: (description || '').trim()
      })
      .where(eq(installments.id, id))
      .returning();

    res.json({
      ...updated[0],
      schedules: schedules || []
    });
  } catch (err) {
    console.error('Error updating installment plan:', err);
    res.status(500).json({ error: 'خطا در ویرایش پرونده اقساط' });
  }
});

// Delete Installment Plan
app.delete('/api/installments/:id', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { id } = req.params;

  try {
    const existing = await db.select()
      .from(installments)
      .where(and(eq(installments.id, id), eq(installments.userId, dbUser.id)));

    if (existing.length === 0) {
      res.status(404).json({ error: 'پرونده اقساط مورد نظر یافت نشد.' });
      return;
    }

    await db.delete(installments).where(eq(installments.id, id));
    res.json({ success: true, message: 'پرونده اقساط با موفقیت حذف شد.' });
  } catch (err) {
    console.error('Error deleting installment:', err);
    res.status(500).json({ error: 'خطا در حذف پرونده اقساط' });
  }
});

// --- Backup/Export/Import ---
app.get('/api/backup/export', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  try {
    const userChecks = await db.select()
      .from(checks)
      .where(eq(checks.userId, dbUser.id))
      .orderBy(desc(checks.createdAt));

    const userInstallments = await db.select()
      .from(installments)
      .where(eq(installments.userId, dbUser.id))
      .orderBy(desc(installments.createdAt));

    const formattedInstallments = userInstallments.map(item => ({
      ...item,
      schedules: JSON.parse(item.schedulesJson || '[]')
    }));

    res.json({
      exporter: dbUser.email,
      exportedAt: new Date().toISOString(),
      checks: userChecks,
      installments: formattedInstallments
    });
  } catch (err) {
    res.status(500).json({ error: 'خطا در صادر کردن اطلاعات پشتیبان' });
  }
});

app.post('/api/backup/import', requireAuth, async (req, res) => {
  const dbUser = (req as any).dbUser;
  const { checks: importData, installments: importInstallments } = req.body;

  if (!Array.isArray(importData) && !Array.isArray(importInstallments)) {
    res.status(400).json({ error: 'فرمت فایل پشتیبان نامعتبر است.' });
    return;
  }

  try {
    let importedCount = 0;
    if (Array.isArray(importData)) {
      for (const item of importData) {
        if (item.insuredName && item.checkOwner && item.checkNumber && item.insuranceType && item.date && item.amount !== undefined) {
          const checkId = item.id || crypto.randomUUID();
          const cleanCheck = {
            id: checkId,
            userId: dbUser.id,
            insuredName: String(item.insuredName).trim(),
            checkOwner: String(item.checkOwner).trim(),
            contactNumber: String(item.contactNumber || '').trim(),
            checkNumber: String(item.checkNumber).trim(),
            insuranceType: String(item.insuranceType).trim(),
            date: String(item.date).trim(),
            amount: Number(item.amount),
            isCleared: !!item.isCleared,
            vehicleInfo: String(item.vehicleInfo || '').trim(),
            description: String(item.description || '').trim(),
            createdAt: item.createdAt || new Date().toISOString()
          };

          await db.insert(checks)
            .values(cleanCheck)
            .onConflictDoUpdate({
              target: checks.id,
              set: {
                insuredName: cleanCheck.insuredName,
                checkOwner: cleanCheck.checkOwner,
                contactNumber: cleanCheck.contactNumber,
                checkNumber: cleanCheck.checkNumber,
                insuranceType: cleanCheck.insuranceType,
                date: cleanCheck.date,
                amount: cleanCheck.amount,
                isCleared: cleanCheck.isCleared,
                vehicleInfo: cleanCheck.vehicleInfo,
                description: cleanCheck.description,
                createdAt: cleanCheck.createdAt
              }
            });
          importedCount++;
        }
      }
    }

    if (Array.isArray(importInstallments)) {
      for (const item of importInstallments) {
        if (item.insuredName && item.policyNumber && item.insuranceType && item.startDate && item.totalAmount !== undefined) {
          const instId = item.id || crypto.randomUUID();
          const cleanInst = {
            id: instId,
            userId: dbUser.id,
            insuredName: String(item.insuredName).trim(),
            policyNumber: String(item.policyNumber).trim(),
            contactNumber: String(item.contactNumber || '').trim(),
            insuranceType: String(item.insuranceType).trim(),
            totalAmount: Number(item.totalAmount),
            installmentCount: Number(item.installmentCount || 1),
            startDate: String(item.startDate).trim(),
            intervalMonths: Number(item.intervalMonths || 1),
            schedulesJson: JSON.stringify(item.schedules || []),
            vehicleInfo: String(item.vehicleInfo || '').trim(),
            description: String(item.description || '').trim(),
            createdAt: item.createdAt || new Date().toISOString()
          };

          await db.insert(installments)
            .values(cleanInst)
            .onConflictDoUpdate({
              target: installments.id,
              set: {
                insuredName: cleanInst.insuredName,
                policyNumber: cleanInst.policyNumber,
                contactNumber: cleanInst.contactNumber,
                insuranceType: cleanInst.insuranceType,
                totalAmount: cleanInst.totalAmount,
                installmentCount: cleanInst.installmentCount,
                startDate: cleanInst.startDate,
                intervalMonths: cleanInst.intervalMonths,
                schedulesJson: cleanInst.schedulesJson,
                vehicleInfo: cleanInst.vehicleInfo,
                description: cleanInst.description,
                createdAt: cleanInst.createdAt
              }
            });
          importedCount++;
        }
      }
    }

    res.json({ success: true, importedCount });
  } catch (err) {
    console.error('Error importing backup:', err);
    res.status(500).json({ error: 'خطا در وارد کردن اطلاعات پشتیبان' });
  }
});

// --- Vite Middleware or Static Assets serving ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running at http://localhost:${PORT}`);
  });
}

startServer();
