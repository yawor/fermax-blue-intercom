import concurrent.futures
import re
import sys
import datetime
from weakref import WeakSet
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from os import PathLike, fsdecode
from pathlib import Path
from types import TracebackType
from typing import (
    Optional,
    Dict,
    Type,
    TypeVar,
    AsyncIterator,
    AsyncContextManager,
    Union,
    Set,
    Callable,
    Awaitable,
    List,
    Any,
    Tuple,
    cast,
)

import json
import logging
import os

import anyio
import httpx
from typing_extensions import Annotated
import pydantic as pd

T = TypeVar("T")
TFermaxBlueClient = TypeVar("TFermaxBlueClient", bound="FermaxBlueClient")

LOGGER = logging.getLogger("fermax_blue")


class TokensData(pd.BaseModel):
    access_token: str
    refresh_token: str
    valid_until: datetime.datetime
    fresh_until: datetime.datetime


class OAuthTokenResponse(pd.BaseModel):
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    jti: str


class AccessId(pd.BaseModel):
    block: int
    subblock: int
    number: int


class AccessDoor(pd.BaseModel):
    title: str
    access_id: AccessId = pd.Field(alias="accessId")
    visible: bool


class Pairing(pd.BaseModel):
    class Config:
        allow_population_by_field_name = True

    id: str
    device_id: str = pd.Field(alias="deviceId")
    tag: str
    status: str
    # updated_at: datetime.datetime = pd.Field(alias="updatedAt")
    # created_at: datetime.datetime = pd.Field(alias="createdAt")
    app_build: str = pd.Field(alias="appBuild")
    app_version: str = pd.Field(alias="appVersion")
    phone_model: str = pd.Field(alias="phoneModel")
    phone_os: str = pd.Field(alias="phoneOS")
    # home: Optional[str]
    # address: Optional[str]
    access_door_map: Dict[str, AccessDoor] = pd.Field(alias="accessDoorMap")
    master: bool


class PairingsResponse(pd.BaseModel):
    __root__: List[Pairing]


class ErrorResponse(pd.BaseModel):
    error: str
    error_description: Optional[str] = None


class Error(Exception):
    pass


class UnauthorizedError(Error):
    pass


class InvalidTokenError(Error):
    pass


class ServerError(Error):
    pass


class UnknownError(Error):
    pass


class InvalidDeviceId(Error):
    pass


class FermaxBlueClient(AbstractAsyncContextManager):
    """
    Fermax Blue client class.
    """

    COMMON_HEADERS = {
        "app-version": "3.2.1",
        # 'accept-language': 'en-ES;q=1.0, es-ES;q=0.9, ru-ES;q=0.8',
        "phone-os": "16.4",
        "user-agent": "Blue/3.2.1 (com.fermax.bluefermax; build:3; iOS 16.4.0) Alamofire/3.2.1",
        "phone-model": "iPad14,5",
        "app-build": "3",
    }

    OAUTH_URL = "https://oauth.blue.fermax.com/oauth/token"
    OAUTH_AUTH = (
        "dpv7iqz6ee5mazm1iq9dw1d42slyut48kj0mp5fvo58j5ih",
        "c7ylkqpujwah85yhnprv0wdvyzutlcnkw4sz90buldbulk1",
    )

    API_BASE_URL = "https://blue.fermax.com"
    # PAIRINGS_ENDPOINT = "/pairing/api/v3/pairings/me"
    # OPEN_DOOR_ENDPOINT = "/deviceaction/api/v1/device/{device_id}/directed-opendoor"

    DEVICE_ID_RE = re.compile(r"^\w+$")

    def __init__(
        self: TFermaxBlueClient, tokens_file_path: Optional[Union[str, bytes, PathLike]]
    ):
        """
        Creates a new instance of FermaxBlueClient.
        :param tokens_file_path: Path to a file containing access and refresh tokens.
            If file is created or updated on successful authentication or token refresh operations.
            The parent directory must already exist and be writable.
            If file exists, tokens are read immediately.
            If set to None, no tokens are read or stored in a file.
        """

        self._tokens_file_path: Optional[Path] = None
        self._tokens: Optional[TokensData] = None

        if tokens_file_path is not None:
            self._tokens_file_path = Path(fsdecode(tokens_file_path)).absolute()
            if self._tokens_file_path.exists():
                try:
                    self._tokens = TokensData.parse_file(self._tokens_file_path)
                except json.JSONDecodeError:
                    # TODO: log errors
                    pass
                except pd.ValidationError as e:
                    # TODO: log errors
                    pass

        self._contextmanager: Optional[AsyncContextManager[TFermaxBlueClient]] = None
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def tokens(self) -> Optional[TokensData]:
        return self._tokens

    @tokens.setter
    def tokens(self, value: TokensData):
        self._tokens = value
        if self._tokens_file_path:
            tmp_file = self._tokens_file_path.with_suffix(".tmp")
            tmp_file.write_text(value.json(), encoding="utf-8")
            tmp_file.replace(self._tokens_file_path)

    def _parse_oauth_response(self, response: httpx.Response):
        if response.is_success:
            data = OAuthTokenResponse.parse_raw(response.content)
            now = datetime.datetime.utcnow()
            self.tokens = TokensData(
                access_token=data.access_token,
                refresh_token=data.refresh_token,
                valid_until=now + datetime.timedelta(seconds=data.expires_in),
                fresh_until=now + datetime.timedelta(seconds=data.expires_in / 2),
            )

        elif response.is_error:
            self._parse_error_response(response)

    @staticmethod
    def _parse_error_response(response: httpx.Response):
        if response.is_client_error:
            try:
                data = ErrorResponse.parse_raw(response.content)
                if data.error == "unauthorized":
                    raise UnauthorizedError(
                        response.status_code, data.error_description
                    )
                elif data.error == "invalid_token":
                    raise InvalidTokenError(
                        response.status_code, data.error_description
                    )
                else:
                    raise UnknownError(
                        response.status_code, data.error, data.error_description
                    )
            except (json.JSONDecodeError, pd.ValidationError):
                raise UnknownError(response.status_code, response.content)
        else:
            raise ServerError(response.status_code, response.content)

    async def authenticate(self, username: str, password: str) -> None:
        assert self._http_client is not None
        response = await self._http_client.post(
            self.OAUTH_URL,
            auth=self.OAUTH_AUTH,
            data={
                "grant_type": "password",
                "username": username,
                "password": password,
            },
        )

        self._parse_oauth_response(response)

    async def refresh_token(self) -> None:
        assert self._http_client is not None
        if self.tokens is None:
            raise InvalidTokenError("Not authenticated")

        response = await self._http_client.post(
            self.OAUTH_URL,
            timeout=15,
            auth=self.OAUTH_AUTH,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self.tokens.refresh_token,
            },
        )

        self._parse_oauth_response(response)

    async def _ensure_fresh_token(self, refresh_token: bool = True) -> None:
        if self.tokens is None:
            raise InvalidTokenError("Not authenticated")

        if datetime.datetime.utcnow() >= self.tokens.fresh_until:
            await self.refresh_token()

    async def get_pairings(self, *, refresh_token: bool = True) -> List[Pairing]:
        assert self._http_client is not None
        await self._ensure_fresh_token(refresh_token)
        assert self.tokens is not None

        response = await self._http_client.get(
            f"{self.API_BASE_URL}/pairing/api/v3/pairings/me",
            headers={"Authorization": f"Bearer {self.tokens.access_token}"},
        )

        if response.is_success:
            return PairingsResponse.parse_raw(response.content).__root__
        elif response.is_error:
            return self._parse_error_response(response)
        else:
            # TODO: Maybe unreachable?
            return []

    async def open_door(
        self, device_id: str, access_id: AccessId, *, refresh_token: bool = True
    ) -> None:
        assert self._http_client is not None
        if self.DEVICE_ID_RE.match(device_id) is None:
            raise InvalidDeviceId()

        await self._ensure_fresh_token(refresh_token)
        assert self.tokens is not None

        response = await self._http_client.post(
            f"{self.API_BASE_URL}/deviceaction/api/v1/device/{device_id}/directed-opendoor",
            headers={
                "Authorization": f"Bearer {self.tokens.access_token}",
                "Content-Type": "application/json",
            },
            content=access_id.json(by_alias=True).encode("utf-8"),
        )

        if response.is_error:
            self._parse_error_response(response)

    @asynccontextmanager
    async def _create_contextmanager(
        self: TFermaxBlueClient,
    ) -> AsyncIterator[TFermaxBlueClient]:
        async with httpx.AsyncClient(headers=self.COMMON_HEADERS) as client:
            self._http_client = client
            try:
                yield self
            finally:
                self._http_client = None

    async def __aenter__(self: TFermaxBlueClient) -> TFermaxBlueClient:
        self._contextmanager = self._create_contextmanager()
        return await self._contextmanager.__aenter__()

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        if self._contextmanager is not None:
            try:
                return await self._contextmanager.__aexit__(
                    exc_type, exc_value, traceback
                )
            finally:
                self._contextmanager = None
        return None


def cli():
    try:
        import typer
        from click import ClickException
    except ModuleNotFoundError:
        print(
            "To use command line, install fermax-blue-intercom[cli] or install typer package manually",
            file=sys.stderr,
        )
        sys.exit(1)

    def format_columns(
        *rows: List[Any],
        start_padding: int = 0,
        column_padding: int = 1,
        column_alignments: Optional[List[str]] = None,
    ) -> str:
        if not len(rows):
            return ""
        column_count = max(map(len, rows))
        if not column_count:
            return ""

        if column_alignments is None:
            column_alignments = [""] * column_count
        elif len(column_alignments) < column_count:
            column_alignments += [""] * (column_count - len(column_alignments))

        padded_rows = [
            list(map(str, row)) + [""] * (column_count - len(row)) for row in rows
        ]
        column_widths = [max(map(len, column)) for column in zip(*padded_rows)]

        output_rows = []
        for row in padded_rows:
            output = " " * start_padding
            for idx, (value, width) in enumerate(zip(row, column_widths)):
                if idx:
                    output += " " * column_padding
                output += "{{value:{}{{width}}}}".format(column_alignments[idx]).format(
                    value=value, width=width
                )

            output_rows.append(output)

        return "\n".join(output_rows)

    class AppContext:
        def __init__(self) -> None:
            self.portal: Optional[anyio.from_thread.BlockingPortal] = None
            self.client: Optional[FermaxBlueClient] = None
            self.futures: Set[concurrent.futures.Future] = cast(
                Set[concurrent.futures.Future], WeakSet()
            )

        def call(self, func: "Callable[..., Awaitable[T]]", *args: object) -> T:
            assert self.portal is not None
            fut = self.portal.start_task_soon(func, *args)
            self.futures.add(fut)
            try:
                return fut.result()
            except KeyboardInterrupt:
                raise typer.Abort()

        def cancel_futures(self):
            for future in self.futures:
                if not future.done():
                    future.cancel()

    app = typer.Typer(chain=True)

    def token_file_path_default_factory():
        try:
            from platformdirs import user_data_dir

            return os.path.join(
                user_data_dir("fermax_blue_intercom", ensure_exists=True), "tokens.json"
            )
        except ModuleNotFoundError:
            # If platformdirs is not installed, no default path is returned
            return None

    @app.callback()
    def app_main(
        ctx: typer.Context,
        token_file: Annotated[
            Optional[Path],
            typer.Option(
                default_factory=token_file_path_default_factory,
                dir_okay=False,
                file_okay=True,
                help="Path to a token file, which stores access and refresh tokens when user authenticates."
                " If platformdirs package is installed, then it is stored in user's"
                " data directory (exact path depends on the operating system).",
            ),
        ],
        no_token_file: Annotated[
            bool,
            typer.Option(
                "--no-token-file",
                show_default=False,
                help="Don't use a token file. This is a default behavior if platformdirs package is not installed.",
            ),
        ] = False,
    ):
        app_ctx = ctx.ensure_object(AppContext)
        # noinspection PyTypeChecker
        app_ctx.portal = ctx.with_resource(anyio.start_blocking_portal())
        app_ctx.client = ctx.with_resource(
            app_ctx.portal.wrap_async_context_manager(
                FermaxBlueClient(None if no_token_file else token_file)
            )
        )

        ctx.call_on_close(app_ctx.cancel_futures)

    @app.command()
    def auth(
        ctx: typer.Context,
        username: Annotated[str, typer.Option(prompt=True, metavar="USERNAME")],
        password: Annotated[
            str, typer.Option(prompt=True, hide_input=True, metavar="PASSWORD")
        ],
    ):
        """
        Authenticates client using username and password. The username and password are not stored locally.
        If username and/or password are not provided as options, the command asks for them interactively.
        """

        app_ctx = ctx.find_object(AppContext)
        assert app_ctx is not None
        assert app_ctx.client is not None

        app_ctx.call(app_ctx.client.authenticate, username, password)

    @app.command()
    def refresh_token(
        ctx: typer.Context,
        force: Annotated[
            bool,
            typer.Option(
                help="Token is refreshed only if it's not fresh anymore (past half of its max age."
                " Use force to refresh token even if it's still fresh."
            ),
        ] = False,
    ):
        """
        Refreshes access token using refresh token acquired after successfully authenticating.
        """

        app_ctx = ctx.find_object(AppContext)
        assert app_ctx is not None
        assert app_ctx.client is not None

        if app_ctx.client.tokens is None:
            print("No tokens saved at the moment. You must first authenticate.")
            raise typer.Exit(1)

        now = datetime.datetime.utcnow()
        if not force and now < app_ctx.client.tokens.fresh_until:
            print("Access-Token is still fresh. No need to refresh it.")
            raise typer.Exit()

        app_ctx.call(app_ctx.client.refresh_token)

    @app.command()
    def pairings(ctx: typer.Context):
        """
        Displays a list of paired devices (monitors) together with associated doors.
        """

        app_ctx = ctx.find_object(AppContext)
        assert app_ctx is not None
        assert app_ctx.client is not None

        pairings_ = app_ctx.call(app_ctx.client.get_pairings)

        print("Pairings:")
        for pairing in pairings_:
            print()
            print(
                format_columns(
                    ["Pairing ID:", pairing.id],
                    ["Tag:", pairing.tag],
                    ["Device ID:", pairing.device_id],
                    ["Master:", pairing.master],
                    ["Status:", pairing.status],
                    ["Access Doors:"],
                    start_padding=2,
                )
            )
            doors: List[Any] = [
                ["ID:", "Title:", "Block:", "SubBlock:", "Number:", "Visible:"]
            ]
            for door_id, door in pairing.access_door_map.items():
                doors.append(
                    [
                        door_id,
                        door.title,
                        door.access_id.block,
                        door.access_id.subblock,
                        door.access_id.number,
                        door.visible,
                    ]
                )

            print(
                format_columns(
                    *doors,
                    start_padding=4,
                    column_padding=4,
                    column_alignments=["", "", ">", ">", ">", ">"],
                )
            )

    access_id_sentinel_value = (-9999, -9999, -9999)

    @app.command()
    def open_door(
        ctx: typer.Context,
        device_id: Annotated[
            Optional[str],
            typer.Option(
                metavar="DEVICE_ID",
                help="Device ID of a paired device (monitor). If not specified,"
                " a request to get pairings is made and first returned device is selected."
                " Device ID can be found by executing pairings command.",
            ),
        ] = None,
        access_id: Annotated[
            Tuple[int, int, int],
            typer.Option(
                metavar="<BLOCK SUBBLOCK NUMBER>",
                show_default=False,
                help="Access ID of a door to open. If not specified, a request to get pairings is made"
                " and first visible door for selected device id is selected."
                " It consists of 3 numbers: Block, SubBlock and Number,"
                " which can be found by executing pairings command."
                " If access id is given, device id also must be provided.",
            ),
        ] = access_id_sentinel_value,
    ):
        """
        Opens door according to specified parameters.
        """

        has_access_id = access_id != access_id_sentinel_value
        if has_access_id and not device_id:
            raise ClickException("Option --device-id is required if --access-id is set")

        app_ctx = ctx.find_object(AppContext)
        assert app_ctx is not None
        assert app_ctx.client is not None

        if not device_id or not has_access_id:
            pairings_ = app_ctx.call(app_ctx.client.get_pairings)
            if device_id:
                pairing = next((x for x in pairings_ if x.device_id == device_id), None)
                if pairing is None:
                    raise ClickException("Provided Device ID not found in pairings")
            else:
                pairing = next(iter(pairings_), None)
                if pairing is None:
                    raise ClickException("No pairings found")
                device_id = pairing.device_id

            access_id_ = next(
                (x.access_id for x in pairing.access_door_map.values() if x.visible),
                None,
            )
            if not access_id_:
                raise ClickException(
                    f"Couldn't find visible access door for device id {device_id}"
                )
        else:
            access_id_ = AccessId(
                block=access_id[0], subblock=access_id[1], number=access_id[2]
            )

        app_ctx.call(app_ctx.client.open_door, device_id, access_id_)

    app()


if __name__ == "__main__":
    cli()
