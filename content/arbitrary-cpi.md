---
заголовок: Arbitrary CPI (Довільний міжпрограмний виклик/запит)
цілі:
- Пояснити ризики безпеки, пов'язані з запитом CPI до невідомої програми
- Показати, як модуль CPI Anchor запобігає цьому (запиту до до невідомої програми) при здійсненні CPI від однієї програми Anchor до іншої
- Безпечно та надійно здійснювати CPI від програми Anchor до довільної не-Anchor програми
---

# TL;DR

- Для генерації CPI, профіль (акаунт) цільової програми повинен бути закладений в інструкцію запиту. Це означає, що в інструкції може бути передана будь-яка цільова програма. Ваша програма повинна перевіряти наявність неправильних чи неочікуваних програм.
- Виконайте перевірки програм в нативних програмах, просто порівнюючи публічний ключ переданої програми з програмою, яку ви очікуєте.
- Якщо програма написана в Anchor, вона може мати загальнодоступний модуль CPI. Завдяки цьому виклик програми з іншої програми Anchor буде простішим і безпечним. Модуль CPI Anchor автоматично перевіряє, що адреса переданої програми відповідає адресі програми, збереженої в модулі.

# Огляд

Cross Program Invocation (CPI) - це міжпрограмний виклик, тобто одна програма викликає інструкцію в іншій програмі. "Довільний CPI" - це коли програма структурована для видачі CPI будь-якій програмі, що передається інструкцією, а не очікує виклику від одної конкретної програми. Враховуючи, що користувачі інструкції вашої програми можуть додати будь-яку програму до список облікових записів інструкції, неможливість перевірити адресу переданої програми призводить до того, що ваша програма виконує CPI для довільних програм.

Відсутність перевірок програм створює можливість зловмисникам передати іншу програму, ніж очікувалося, що призведе до виклику інструкції оригінальною програмою до цієї загадкової (програми зловмисника). Немає можливості передбачити наслідки цього CPI. Вони залежать від логіки програми (як оригінальної, так і невідомої програми), а також від інших профілів (акаунтів), які вже вписані в оригінальну інструкцію.

## Перевірка/пошук втрачених програм

Візьмемо для прикладу наступну програму. Інструкція `cpi` викликає інструкцію `transfer` на `token_program`, але в ній відсутній код, який перевіряє, чи рахунок `token_program`, переданий в інструкцію, фактично є SPL Token Program.

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod arbitrary_cpi_insecure {
    use super::*;

    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.source.clone(),
                ctx.accounts.destination.clone(),
                ctx.accounts.authority.clone(),
            ],
        )
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: UncheckedAccount<'info>,
    destination: UncheckedAccount<'info>,
    authority: UncheckedAccount<'info>,
    token_program: UncheckedAccount<'info>,
}
```

Злоумисник може легко викликати цю інструкцію і передати копію token program, яку він створив і контролює.
## Додавання перевірки програм

Це можна виправити, просто додавши кілька рядків до інструкції `cpi` для перевірки того, чи ключ програми `token_program` відповідає публічному ключу SPL Token Program.

```rust
pub fn cpi_secure(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
    if &spl_token::ID != ctx.accounts.token_program.key {
        return Err(ProgramError::IncorrectProgramId);
    }
    solana_program::program::invoke(
        &spl_token::instruction::transfer(
            ctx.accounts.token_program.key,
            ctx.accounts.source.key,
            ctx.accounts.destination.key,
            ctx.accounts.authority.key,
            &[],
            amount,
        )?,
        &[
            ctx.accounts.source.clone(),
            ctx.accounts.destination.clone(),
            ctx.accounts.authority.clone(),
        ],
    )
}
```
Тепер, якщо зловмисник передасть іншу токен програму, інструкція видасть помилку `ProgramError::IncorrectProgramId`.

Залежно від програми, яку ви викликаєте вашою CPI, ви можете або захардкодити (дані зашиваються жорстко в програму і не можуть бути змінені без правки коду програми) адресу ID очікуваної програми, або використовувати крейт Rust програми для отримання адреси програми, якщо це можливо. У прикладі вище крейт `spl_token` надає адресу SPL Token Program.

## Використання модуля Anchor CPI

Простіший спосіб провести перевірку програми - використати модулі Anchor CPI. Ми вивчили в [попередньому уроці](https://github.com/Unboxed-Software/solana-course/blob/main/content/anchor-cpi), що Anchor может автоматично генерувати модулі CPI для спрощення включення CPI в програму. Ці модулі також підвищують безпеку, перевіряючи публічний ключ програми, який передається в одну з її публічних інструкцій.

Кожна програма Anchor використовує макрос `declare_id()` для визначення адреси програми. Коли CPI модуль генерується для певної програми, він використовує адресу, передану у цей макрос, як "source of truth" ("джерело правди") і автоматично перевіряє, що всі CPI, викликані за допомогою його CPI модулю, спрямовані на цей ID програми.

Хоча фундаментально використання модулів CPI не відрізняється від ручної перевірки, але воно виключає можливість забути про виконання перевірки програми чи випадково ввести неправильний ідентифікатор програми під час жорсткого кодування (хардкодингу).

Програма нижче показує приклад використання модуля CPI для програми SPL Token для виконання переказу, показаного в попередніх прикладах.

```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod arbitrary_cpi_recommended {
    use super::*;

    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        token::transfer(ctx.accounts.transfer_ctx(), amount)
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: Account<'info, TokenAccount>,
    destination: Account<'info, TokenAccount>,
    authority: Signer<'info>,
    token_program: Program<'info, Token>,
}

impl<'info> Cpi<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.source.to_account_info(),
            to: self.destination.to_account_info(),
            authority: self.authority.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}
```

Зверніть увагу, що, подібно до прикладу вище, Anchor створив [обгортки для популярних нативних програм](https://github.com/coral-xyz/anchor/tree/master/spl/src), які дозволяють вам викликати CPI, якщо вони були програмами Anchor.

В залежності від програми, до якої ви робите CPI, ви можете використовувати тип облікового запису Anchor [`Program` account type](https://docs.rs/anchor-lang/latest/anchor_lang/accounts/program/struct.Program.html), щоб підтвердити програму в структурі перевірки облікового запису. Між крейтами [`anchor_lang`](https://docs.rs/anchor-lang/latest/anchor_lang) та [`anchor_spl`](https://docs.rs/anchor_spl/latest/) надаються за замовчуванням такі типи `Program`:

- [`System`](https://docs.rs/anchor-lang/latest/anchor_lang/struct.System.html)
- [`AssociatedToken`](https://docs.rs/anchor-spl/latest/anchor_spl/associated_token/struct.AssociatedToken.html)
- [`Token`](https://docs.rs/anchor-spl/latest/anchor_spl/token/struct.Token.html)

If you have access to an Anchor program's CPI module, you typically can import its program type with the following, replacing the program name with the name of the actual program:
Якщо у вас є доступ до CPI модуля Anchor програми, ви зазвичай можете імпортувати його тип програми за допомогою наступного коду, замінюючи ім'я програми на ім'я фактичної програми:


```rust
use other_program::program::OtherProgram;
```

# Практична частина

Щоб продемонструвати важливість перевірки програм, проведемо спрощену та дещо вигадану гру. Ця гра представляє персонажів з PDA профілями і використовує окрему програму "metadata" для управління метаданими персонажів та атрибутами, такими як здоров'я і потужність.

Хоча цей приклад, до певної міри, придуманий, він має майже ідентичну архітектуру, як NFT на Solana: програма SPL Token відповідає за створення (Token Mints), розподіл і переказ, а окрема програма метаданих використовується для призначення метаданих і облікових записів. Таким чином, уразливість, яку ми розглядаємо тут, також може бути застосована до реальних токенів.

Вихідний код для гри знаходиться в папці arbitrary-cpi. Якщо ви ще цього не зробили, склонуйте репозиторій і змініть гілку на main.

### 1. Налаштування

"Ми розпочнемо з гілки `starter` у [цьому репозиторії](https://github.com/Unboxed-Software/solana-arbitrary-cpi/tree/starter). Склонуйте репозиторій, а потім відкрийте його в гілці `starter`."

Зверніть увагу, що є три програми:

1. `gameplay`
2. `character-metadata`
3. `fake-metadata`

Крім того, вже є тест у директорії `tests`.

Перша програма, `gameplay`, та, яку безпосередньо використовує наш тест. Ознайомтеся з програмою. Вона має дві інструкції:

1. `create_character_insecure` - створює нового персонажа та використовує CPI для налаштування початкових атрибутів персонажа в програмі метаданих.
2. `battle_insecure` - ставить двох персонажів одного проти одного, присвоюючи "win" (перемогу) персонажу з найвищими атрибутами.

Друга програма, `character-metadata`, призначена бути "approved" (схваленою/підтвердженою) програмою для обробки метаданих персонажа. Погляньте на цю програму. Вона має одну інструкцію для `create_metadata`, яка створює новий PDA та призначає псевдовипадкове значення від 0 до 20 для здоров'я та сили персонажа.

Остання програма, `fake-metadata`, є "фейковою" програмою метаданих, призначеною для ілюстрації того, як атакуючий може використовувати нашу програму `gameplay`. Ця програма майже ідентична програмі `character-metadata`, за винятком того, що вона призначає початкове здоров'я та силу персонажа максимально допустимими: 255.

### 2. Протестуйте інструкцію `create_character_insecure`.

Для цього вже існує тест у директорії `tests`. Він трошки довгий, але присвятіть хвилину, щоб ознайомитися з ним, перш ніж ми обговоримо його разом:

```typescript
it("Insecure instructions allow attacker to win every time", async () => {
    // Initialize player one with real metadata program
    await gameplayProgram.methods
      .createCharacterInsecure()
      .accounts({
        metadataProgram: metadataProgram.programId,
        authority: playerOne.publicKey,
      })
      .signers([playerOne])
      .rpc()

    // Initialize attacker with fake metadata program
    await gameplayProgram.methods
      .createCharacterInsecure()
      .accounts({
        metadataProgram: fakeMetadataProgram.programId,
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc()

    // Fetch both player's metadata accounts
    const [playerOneMetadataKey] = getMetadataKey(
      playerOne.publicKey,
      gameplayProgram.programId,
      metadataProgram.programId
    )

    const [attackerMetadataKey] = getMetadataKey(
      attacker.publicKey,
      gameplayProgram.programId,
      fakeMetadataProgram.programId
    )

    const playerOneMetadata = await metadataProgram.account.metadata.fetch(
      playerOneMetadataKey
    )

    const attackerMetadata = await fakeMetadataProgram.account.metadata.fetch(
      attackerMetadataKey
    )

    // The regular player should have health and power between 0 and 20
    expect(playerOneMetadata.health).to.be.lessThan(20)
    expect(playerOneMetadata.power).to.be.lessThan(20)

    // The attacker will have health and power of 255
    expect(attackerMetadata.health).to.equal(255)
    expect(attackerMetadata.power).to.equal(255)
})
```

Цей тест відіграє сценарій, де звичайний і атакуючий гравці створюють своїх персонажів. Тільки атакувальник передає ідентифікатор програми фальшивих метаданих замість справжньої програми з метаданими. І оскільки інструкція `create_character_insecure` не має перевірок програми, вона все ще виконується.

Результатом є те, що звичайний персонаж має відповідну кількість здоров'я і сили: значення в межах від 0 до 20. Водночас, здоров'я та сила атакуючого складають 255, що робить його непереможним.

Якщо ви ще цього не зробили, виконайте `anchor test`, щоб переконатися, що цей тест дійсно поводить себе так, як описано.

### 3. Створення інструкції `create_character_secure`

Давайте виправимо це, створивши безпечну інструкцію для створення нового персонажа. Ця інструкція повинна реалізовувати належні перевірки програми та використовувати криптограму `cpi` програми `character-metadata` для виконання CPI, а не просто використовувати `invoke`.

Якщо ви хочете випробувати свої навички, спробуйте зробити це самостійно, перш ніж рухатися вперед.

Ми розпочнемо з оновлення нашого оператора `use` у верхній частині файлу `lib.rs` програми `gameplay`. Ми даємо собі доступ до типу програми для перевірки обліку та допоміжної функції для виклику CPI `create_metadata`.

```rust
use character_metadata::{
    cpi::accounts::CreateMetadata,
    cpi::create_metadata,
    program::CharacterMetadata,
};
```

Давайте створимо нову структуру для перевірки облікового запису з іменем `CreateCharacterSecure`. На цей раз зробимо `metadata_program` типом `Program`:

```rust
#[derive(Accounts)]
pub struct CreateCharacterSecure<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32 + 64,
        seeds = [authority.key().as_ref()],
        bump
    )]
    pub character: Account<'info, Character>,
    #[account(
        mut,
        seeds = [character.key().as_ref()],
        seeds::program = metadata_program.key(),
        bump,
    )]
    /// CHECK: manual checks
    pub metadata_account: AccountInfo<'info>,
    pub metadata_program: Program<'info, CharacterMetadata>,
    pub system_program: Program<'info, System>,
}
```

Наостанок додамо інструкцію `create_character_secure`. Вона буде такою ж, як і раніше, але використовуватиме повні функціональні можливості Anchor CPIs, а не безпосередньо `invoke`:

```rust
pub fn create_character_secure(ctx: Context<CreateCharacterSecure>) -> Result<()> {
    let character = &mut ctx.accounts.character;
    character.metadata = ctx.accounts.metadata_account.key();
    character.auth = ctx.accounts.authority.key();
    character.wins = 0;

    let context = CpiContext::new(
        ctx.accounts.metadata_program.to_account_info(),
        CreateMetadata {
            character: ctx.accounts.character.to_account_info(),
            metadata: ctx.accounts.metadata_account.to_owned(),
            authority: ctx.accounts.authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        },
    );

    create_metadata(context)?;

    Ok(())
}
```

### 4. Тест `create_character_secure`

Now that we have a secure way of initializing a new character, let's create a new test. This test just needs to attempt to initialize the attacker's character and expect an error to be thrown.
Тепер, коли у нас є безпечний спосіб ініціалізації нового персонажа, давайте створимо новий тест. Цей тест просто повинен намагатися ініціалізувати атакуючого персонажа і очікувати виникнення помилки.

```typescript
it("Secure character creation doesn't allow fake program", async () => {
    try {
      await gameplayProgram.methods
        .createCharacterSecure()
        .accounts({
          metadataProgram: fakeMetadataProgram.programId,
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc()
    } catch (error) {
      expect(error)
      console.log(error)
    }
})
```

Якщо ще не використовували, запустіть команду `anchor test`. Зверніть увагу, що, як і очікувалося, виникла помилка, в якій детально вказано, що наданий ідентифікатор програми в інструкцію не є очікуваним ідентифікатором програми:

```bash
'Program log: AnchorError caused by account: metadata_program. Error Code: InvalidProgramId. Error Number: 3008. Error Message: Program ID was not as expected.',
'Program log: Left:',
'Program log: FKBWhshzcQa29cCyaXc1vfkZ5U985gD5YsqfCzJYUBr',
'Program log: Right:',
'Program log: D4hPnYEsAx4u3EQMrKEXsY3MkfLndXbBKTEYTwwm25TE'
```

Це все, що вам потрібно зробити, щоб захиститися від довільних CPI!

Іноді вам може знадобитися більше гнучкості у CPI вашої програми. Ми, звісно, не забороняємо вам створювати програму, яка вам потрібна, але, будь ласка, вживайте всі можливі заходи безпеки, щоб уникнути вразливостей у своїй програмі.

Якщо ви хочете переглянути остаточний код рішення, ви можете знайти його на гілці `solution` в [тому ж репозиторії](https://github.com/Unboxed-Software/solana-arbitrary-cpi/tree/solution).

# Виклик

Так само, як і з іншими уроками в цьому блоку, найкраща можливість практикуватися полягає в аудиті власних або інших програм.

Візьміть собі час для огляду принаймні однієї програми та переконайтеся, що перевірки програми виконуються для кожної програми, яка передається в інструкції, особливо тих, які викликаються через CPI.

Не забувайте, якщо ви знаходите помилку або вразливість у програмі іншої людини, будь ласка, попередьте їх! Якщо ви знаходите їх у власній програмі, обов'язково виправте їх негайно.

## Завершили лабораторну?

Виведіть свій код на GitHub і [поділіться своїми враженнями від цього уроку](https://form.typeform.com/to/IPH0UGz7#answers-lesson=5bcaf062-c356-4b58-80a0-12cca99c29b0)!
